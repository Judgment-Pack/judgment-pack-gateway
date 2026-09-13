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
)

// connectRequest is what the operator asked `connect` to write: a platform
// entry, in the terms the configuration file uses.
type connectRequest struct {
	config      string
	platform    string
	binding     string // a catalog name; the pin is computed here
	credentials string // the path as written; never a value
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

const connectUsage = "usage: gateway connect --config <engine.json> <platform> --binding <name> --credentials-file <path> --user <name> [--endpoint HOST] [--environment KEY=VALUE]... [--write] [--replace]"

// cmdConnect writes a platform entry into the engine's configuration:
// after holding the configuration it would produce to every refusal
// `serve` applies, and after each of the platform's adapters, run once in
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
	outcome, err := connect(ctx, req, osEngineHost(), checkAsUser)
	for _, statement := range outcome.statements {
		fmt.Fprintln(os.Stderr, "connect:", statement)
	}
	for _, answer := range outcome.answers {
		fmt.Fprintln(os.Stdout, answer)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect:", err)
		return 1
	}
	fmt.Fprintf(os.Stdout, "%s: written to %s\n", req.platform, outcome.written)
	return 0
}

// parseConnectArgs reads the command line; the platform is the one
// positional argument, first or last.
func parseConnectArgs(args []string) (connectRequest, string, bool) {
	var req connectRequest
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		req.platform, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&req.config, "config", "", "")
	fs.StringVar(&req.binding, "binding", "", "")
	fs.StringVar(&req.credentials, "credentials-file", "", "")
	fs.StringVar(&req.user, "user", "", "")
	fs.StringVar(&req.endpoint, "endpoint", "", "")
	fs.Func("environment", "", func(s string) error { req.environment = append(req.environment, s); return nil })
	fs.BoolVar(&req.write, "write", false, "")
	fs.BoolVar(&req.replace, "replace", false, "")
	if err := fs.Parse(args); err != nil {
		return req, connectUsage + "\n" + err.Error(), false
	}
	rest := fs.Args()
	if req.platform == "" && len(rest) == 1 {
		req.platform, rest = rest[0], nil
	}
	if len(rest) != 0 || req.platform == "" || req.config == "" || req.binding == "" || req.credentials == "" || req.user == "" {
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
	// The file must be one this command can put in place, judged before
	// any adapter is run for nothing.
	if err := regularFile(req.config); err != nil {
		return out, err
	}
	data, err := readBounded(req.config, maxEngineConfigBytes)
	if err != nil {
		return out, fmt.Errorf("engine configuration: %v", err)
	}
	cfg, err := parseEngineConfig(data)
	if err != nil {
		return out, err
	}
	// Every platform already configured is resolved too: a pin the
	// catalog no longer digests to is found here, not at the next start.
	bindings, err := resolveEngineConfig(&cfg, host.account)
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
	ref, b, err := pinBinding(cfg.catalog, req.binding)
	if err != nil {
		return out, err
	}
	entry, err := newPlatformEntry(req, ref, host.account)
	if err != nil {
		return out, err
	}
	// The configuration as it would be, held to every refusal serve
	// applies -- with the new entry in place of the old when replacing,
	// so the old entry's user does not collide with its own.
	candidate := cfg
	candidate.platforms = append([]platformConfig(nil), cfg.platforms...)
	if index >= 0 {
		candidate.platforms[index] = entry
	} else {
		candidate.platforms = append(candidate.platforms, entry)
	}
	sort.Slice(candidate.platforms, func(i, j int) bool { return candidate.platforms[i].name < candidate.platforms[j].name })
	bindings[req.platform] = b
	statements, err := engineRefusals(&candidate, host)
	if err != nil {
		return out, err
	}
	out.statements = statements
	// The platform's own sources, each asked once; the first that cannot
	// answer ends the connect, and nothing is written.
	sources := deriveSources(candidate, bindings)
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
	if err := writePlatformEntry(req.config, data, req, ref); err != nil {
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
// under the rules the parser applies to one it reads.
func newPlatformEntry(req connectRequest, ref string, account func(name string) (int, string, error)) (platformConfig, error) {
	p := platformConfig{name: req.platform, binding: ref, user: req.user, endpoint: req.endpoint, write: req.write}
	credentials, err := cleanAbsolutePath("credentials-file", req.credentials)
	if err != nil {
		return p, err
	}
	p.credentials = credentials
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

// checkAsUser runs an adapter's check as the platform's user, as serve
// would run its acquisitions, refusing first when this process cannot
// switch.
func checkAsUser(ctx context.Context, spec sourceSpec) ([]byte, error) {
	if err := requireUserSwitching(map[string]sourceSpec{"check": spec}); err != nil {
		return nil, err
	}
	return runCheck(ctx, spec)
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
	argv := append([]string{spec.argv[0], "--check", "--timeout", checkTimeout.String()}, spec.argv[1:]...)
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
	if err := cmd.Start(); err != nil {
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
		return who + ": server " + server + ", protocol " + check.ProtocolVersion + ", tools " + strings.Join(check.Tools, ", "), nil
	}
	return "", fmt.Errorf("no check for shape %q", shape)
}

// writePlatformEntry puts the entry into the configuration file as
// written, in the engine's own form: the file re-read as a value, the
// platform set under platforms, the whole written out with members in
// canonical order, and put in place by a rename so a reader sees the old
// file or the new and never a partial one.
func writePlatformEntry(path string, data []byte, req connectRequest, ref string) error {
	v, err := parseJSON(data)
	if err != nil {
		return fmt.Errorf("engine configuration: %v", err)
	}
	obj, err := requireObject(v, "engine configuration")
	if err != nil {
		return err
	}
	platformsValue, _ := obj.get("platforms")
	platforms, err := requireObject(platformsValue, "platforms")
	if err != nil {
		return err
	}
	entry := newObject()
	entry.set("binding", vString(ref))
	credentials := newObject()
	credentials.set("file", vString(req.credentials))
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
	return replaceFile(path, []byte(sb.String()))
}

// regularFile is why path is not a file this command writes, or nil.
func regularFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("engine configuration: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("engine configuration: %s is a symbolic link; name the file itself", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("engine configuration: %s is not a regular file", path)
	}
	return nil
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

// replaceFile writes content beside path and renames it into place,
// keeping the file's mode. A path that is a symbolic link is refused: the
// operator names the file, and the link's owner would otherwise choose
// which file the entry lands in.
func replaceFile(path string, content []byte) error {
	if err := regularFile(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("engine configuration: %v", err)
	}
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	tmp := path + ".connect-" + hex.EncodeToString(suffix[:])
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		return fmt.Errorf("engine configuration: %v", err)
	}
	fail := func(err error) error {
		file.Close()
		os.Remove(tmp)
		return fmt.Errorf("engine configuration: %v", err)
	}
	if _, err := file.Write(content); err != nil {
		return fail(err)
	}
	if err := file.Sync(); err != nil {
		return fail(err)
	}
	if err := file.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("engine configuration: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("engine configuration: %v", err)
	}
	return nil
}
