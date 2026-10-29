package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"adapters/internal/sandbox"
)

// executableIdentity is what a customer command's approval binds (snapshot
// version 4): the file the command resolves to, by its absolute path with
// links resolved, and its digest; when that file is a "#!" script, each
// program the kernel or env runs before it (Interpreters, in the order they
// run); and, when an operand names a regular file -- the script an
// interpreter runs -- that file the same way. Code an interpreter or a
// package runner loads by other means (a module name, a download), and the
// shared libraries a binary loads, are not bound.
type executableIdentity struct {
	Digest       string         `json:"digest"`
	Interpreters []fileIdentity `json:"interpreters,omitempty"`
	Path         string         `json:"path"`
	Script       *fileIdentity  `json:"script,omitempty"`
}

type fileIdentity struct {
	Digest string `json:"digest"`
	Path   string `json:"path"`
}

// maxInterpreters bounds the "#!" chain bound: the kernel follows at most a
// few levels, and env adds one program per level.
const maxInterpreters = 8

// measuredCommand is a customer command resolved and digested for one start.
// file holds the bytes digested: on Linux a binary's sealed in-memory copy,
// which is what is executed; otherwise the command's file opened once, which
// the caller closes. workspace and env are what the "#!" chain was resolved
// against, kept for the re-check before the start.
type measuredCommand struct {
	identity  executableIdentity
	file      *os.File
	workspace string
	env       []string
}

// resolveCustomerWord is the absolute path, links resolved, a command word
// names: an absolute path as written; a relative path against the workspace,
// the directory the server runs in; a bare name on this process's PATH.
func resolveCustomerWord(word, workspace string, lookup bool) (string, error) {
	path := word
	switch {
	case filepath.IsAbs(word):
	case strings.ContainsRune(word, '/') || strings.ContainsRune(word, filepath.Separator) || !lookup:
		path = filepath.Join(workspace, word)
	default:
		found, err := exec.LookPath(word)
		if err != nil {
			return "", err
		}
		if path, err = filepath.Abs(found); err != nil {
			return "", err
		}
	}
	return filepath.EvalSymlinks(path)
}

// measureCustomerCommand resolves the command, its "#!" chain and its script
// operand afresh and digests each. env is the server's environment: env
// finds a "#!/usr/bin/env NAME" program on its PATH. A binary is copied into
// a sealed in-memory file where the platform has one, and digested from that
// copy, which is what then runs; any other file is digested from a
// descriptor opened once. The caller closes m.file.
func measureCustomerCommand(command []string, workspace string, env []string) (*measuredCommand, error) {
	path, err := resolveCustomerWord(command[0], workspace, true)
	if err != nil {
		return nil, fmt.Errorf("server command could not be resolved: %v", err)
	}
	file, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	if !startsWithShebang(file) {
		// The bytes digested are the bytes executed: a writer of the file
		// can no longer change them between the digest and the start.
		if sealed, err := sandbox.SealedCopy(file, filepath.Base(path)); err == nil {
			file.Close()
			file = sealed
		}
	}
	digest, err := digestOf(file)
	if err != nil {
		file.Close()
		return nil, err
	}
	m := &measuredCommand{identity: executableIdentity{Digest: digest, Path: path}, file: file, workspace: workspace, env: env}
	if m.identity.Interpreters, err = interpreterChain(file, workspace, env); err != nil {
		file.Close()
		return nil, err
	}
	// The first operand that names a regular file is the script: an
	// option's separate value that is not a file (-X dev) is passed over,
	// one that is (--require hook.js) is taken for the script.
	for _, word := range command[1:] {
		if strings.HasPrefix(word, "-") {
			continue
		}
		script, err := resolveCustomerWord(word, workspace, false)
		if err != nil {
			continue
		}
		if info, err := os.Stat(script); err != nil || !info.Mode().IsRegular() {
			continue
		}
		identity, err := digestPath(script)
		if err != nil {
			file.Close()
			return nil, err
		}
		m.identity.Script = &identity
		break
	}
	return m, nil
}

// interpreterChain is what runs a "#!" script before it, bound by path and
// digest in the order it runs: the interpreter its first line names, resolved
// against the workspace (the server's working directory) when relative;
// for env, the program env runs, found on the server's PATH; and so on while
// what runs is itself a "#!" script. A file that is not one has no chain.
func interpreterChain(file *os.File, workspace string, env []string) ([]fileIdentity, error) {
	var chain []fileIdentity
	current := file
	defer func() {
		if current != file {
			current.Close()
		}
	}()
	for startsWithShebang(current) {
		interpreter, argument, err := shebangLine(current)
		if err != nil {
			return nil, err
		}
		path, err := resolveCustomerWord(interpreter, workspace, false)
		if err != nil {
			return nil, fmt.Errorf("mcp-executable-unbindable: the #! interpreter could not be resolved: %v", err)
		}
		programs := []string{path}
		if filepath.Base(interpreter) == "env" || filepath.Base(path) == "env" {
			name, err := envProgram(argument)
			if err != nil {
				return nil, err
			}
			found, err := lookPathIn(name, workspace, env)
			if err != nil {
				return nil, err
			}
			programs = append(programs, found)
		}
		for _, program := range programs {
			if len(chain) == maxInterpreters {
				return nil, errors.New("mcp-executable-unbindable: the #! chain is longer than this adapter binds")
			}
			next, err := openRegular(program)
			if err != nil {
				return nil, err
			}
			if current != file {
				current.Close()
			}
			current = next
			digest, err := digestOf(current)
			if err != nil {
				return nil, err
			}
			chain = append(chain, fileIdentity{Digest: digest, Path: program})
		}
	}
	return chain, nil
}

// startsWithShebang reports whether the file begins with "#!".
func startsWithShebang(f *os.File) bool {
	var head [2]byte
	n, _ := f.ReadAt(head[:], 0)
	return n == 2 && head[0] == '#' && head[1] == '!'
}

// shebangLine reads a "#!" line as the Linux kernel does: within its first
// 256 bytes, the interpreter is the first word after "#!", and the rest of
// the line, trimmed, is one optional argument.
func shebangLine(f *os.File) (interpreter, argument string, err error) {
	buf := make([]byte, 256)
	n, _ := f.ReadAt(buf, 0)
	line := string(buf[2:n])
	end := strings.IndexByte(line, '\n')
	if end < 0 {
		if n == len(buf) {
			return "", "", errors.New("mcp-executable-unbindable: the #! line is longer than the kernel reads")
		}
		end = len(line)
	}
	line = strings.TrimLeft(line[:end], " \t")
	interpreter, argument, _ = strings.Cut(strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		return r
	}, line), " ")
	if interpreter == "" || strings.ContainsRune(interpreter, 0) {
		return "", "", errors.New("mcp-executable-unbindable: the #! line names no interpreter")
	}
	return interpreter, strings.TrimSpace(argument), nil
}

// envProgram is the program a "#!/usr/bin/env ARGUMENT" line runs, or a
// refusal: not every env variant is bound, only two forms are accepted.
//   - Without -S, ARGUMENT is one plain program word (the kernel hands env
//     the whole rest of the line as one argument).
//   - With -S, which splits the string, the first word is one plain program
//     word and the rest are literal arguments.
//
// A plain word is not an option, not an assignment, and holds nothing env -S
// would expand or unquote ("$", a backslash, a quote, "#"); and the program
// is not env itself, whose own arguments would choose another program. Any
// other form refuses with mcp-executable-unbindable.
func envProgram(argument string) (string, error) {
	unbindable := func(why string) (string, error) {
		return "", errors.New("mcp-executable-unbindable: the #! line's env " + why + ", so the program it runs is not bound")
	}
	words := []string{argument}
	if rest, ok := strings.CutPrefix(argument, "-S"); ok {
		words = strings.Fields(rest)
		if len(words) == 0 {
			return unbindable("runs no program")
		}
	}
	for _, word := range words {
		if strings.ContainsAny(word, "$\\'\"#`") || (len(words) == 1 && strings.ContainsAny(word, " \t")) {
			return unbindable("has an expansion, an escape or a quote")
		}
	}
	name := words[0]
	switch {
	case name == "" || strings.HasPrefix(name, "-"):
		return unbindable("has an option other than -S")
	case strings.ContainsRune(name, '='):
		return unbindable("has a variable assignment")
	case filepath.Base(name) == "env":
		return unbindable("runs env again")
	}
	return name, nil
}

// lookPathIn finds name as env does (execvp): a name with a slash relative to
// the working directory; otherwise the first executable regular file in a
// directory of the PATH in env (the C library's default when it has none),
// an empty or relative entry taken against the working directory.
func lookPathIn(name, workspace string, env []string) (string, error) {
	if strings.ContainsRune(name, '/') {
		return resolveCustomerWord(name, workspace, false)
	}
	path := "/bin:/usr/bin"
	for _, pair := range env {
		if value, ok := strings.CutPrefix(pair, "PATH="); ok {
			path = value
		}
	}
	for _, dir := range strings.Split(path, ":") {
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(workspace, dir)
		}
		candidate := filepath.Join(dir, name)
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return filepath.EvalSymlinks(candidate)
		}
	}
	return "", fmt.Errorf("mcp-executable-unbindable: env's program %q is not on the server's PATH", name)
}

// openRegular opens a regular file without blocking: a FIFO or a device at
// the path neither blocks the start nor is read, and refuses.
func openRegular(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|nonBlocking, 0)
	if err != nil {
		return nil, fmt.Errorf("server executable could not be read for its digest: %w", err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("server executable %s is not a regular file", path)
	}
	return file, nil
}

// digestOf digests everything file holds from its first byte, leaving its
// offset alone.
func digestOf(file *os.File) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(file, 0, 1<<62)); err != nil {
		return "", fmt.Errorf("server executable could not be read for its digest: %w", err)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// digestPath opens a regular file at path and digests it.
func digestPath(path string) (fileIdentity, error) {
	file, err := openRegular(path)
	if err != nil {
		return fileIdentity{}, err
	}
	defer file.Close()
	digest, err := digestOf(file)
	return fileIdentity{Digest: digest, Path: path}, err
}

// approvedCommandRefusal is why a measured command is not the approved one.
func approvedCommandRefusal(approved *executableIdentity, measured executableIdentity) error {
	switch {
	case approved == nil:
		return errors.New("mcp-approval-reapproval-required: the approval binds no executable; approve the source again")
	case approved.Path != measured.Path:
		return errors.New("mcp-executable-changed: the command now resolves to another file than the approved one")
	case approved.Digest != measured.Digest:
		return errors.New("mcp-executable-changed: the command's file differs from the approved digest")
	case (approved.Script == nil) != (measured.Script == nil):
		return errors.New("mcp-executable-changed: the command's script operand differs from the approved one")
	case approved.Script != nil && approved.Script.Path != measured.Script.Path:
		return errors.New("mcp-executable-changed: the script now resolves to another file than the approved one")
	case approved.Script != nil && approved.Script.Digest != measured.Script.Digest:
		return errors.New("mcp-executable-changed: the script differs from the approved digest")
	}
	return interpreterRefusal(approved.Interpreters, measured.Interpreters)
}

// interpreterRefusal is why a measured "#!" chain is not the approved one.
func interpreterRefusal(approved, measured []fileIdentity) error {
	if len(approved) != len(measured) {
		return errors.New("mcp-executable-changed: the #! interpreters differ from the approved ones")
	}
	for i := range approved {
		if approved[i].Path != measured[i].Path {
			return errors.New("mcp-executable-changed: a #! interpreter now resolves to another file than the approved one")
		}
		if approved[i].Digest != measured[i].Digest {
			return errors.New("mcp-executable-changed: a #! interpreter differs from the approved digest")
		}
	}
	return nil
}

// recheckBeforeStart digests again, immediately before the start, each file
// that is not executed as the exact bytes digested: the script operand always
// (its interpreter opens it by path); the command's file when the backend
// executes it by path or through a descriptor that is not a sealed copy; and
// the "#!" chain, resolved afresh, which the kernel and env open by path. A
// change in between refuses the start.
func recheckBeforeStart(m *measuredCommand, exact bool) error {
	if !exact {
		file, err := openRegular(m.identity.Path)
		if err != nil {
			return err
		}
		digest, err := digestOf(file)
		if err == nil && digest == m.identity.Digest {
			var chain []fileIdentity
			chain, err = interpreterChain(file, m.workspace, m.env)
			if err == nil && interpreterRefusal(m.identity.Interpreters, chain) != nil {
				err = errors.New("mcp-executable-changed: a #! interpreter changed between its digest and its start")
			}
		} else if err == nil {
			err = errors.New("mcp-executable-changed: the command's file changed between its digest and its start")
		}
		file.Close()
		if err != nil {
			return err
		}
	}
	if s := m.identity.Script; s != nil {
		identity, err := digestPath(s.Path)
		if err != nil {
			return err
		}
		if identity.Digest != s.Digest {
			return errors.New("mcp-executable-changed: the script changed between its digest and its start")
		}
	}
	return nil
}

// loaderVariableRefusal refuses a customer command whose environment -- the
// platform's configured environment this adapter runs with, or a credentials
// member -- names a variable the dynamic loader honours. It names neither the
// variable nor its value: a credentials member's name may be another's value.
func loaderVariableRefusal(environment, credentials []string) error {
	for _, set := range []struct {
		pairs []string
		what  string
	}{{environment, "the configured environment"}, {credentials, "a credentials member"}} {
		for _, pair := range set.pairs {
			name, _, _ := strings.Cut(pair, "=")
			if sandbox.LoaderVariable(name) {
				return fmt.Errorf("sandbox-loader-variable-refused: %s names a dynamic-loader variable (LD_*, DYLD_* or GCONV_PATH), which a customer command may not carry", set.what)
			}
		}
	}
	return nil
}
