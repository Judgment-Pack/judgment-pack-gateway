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
// links resolved, and its digest; and, when the first operand names a
// regular file -- the script an interpreter runs -- that file the same way.
// Code an interpreter or a package runner loads by other means (a module
// name, a download) is not bound.
type executableIdentity struct {
	Digest string        `json:"digest"`
	Path   string        `json:"path"`
	Script *fileIdentity `json:"script,omitempty"`
}

type fileIdentity struct {
	Digest string `json:"digest"`
	Path   string `json:"path"`
}

// measuredCommand is a customer command resolved and digested for one start:
// file is the command's file opened once, the descriptor its digest was read
// from and, where the platform allows, the descriptor that is executed.
type measuredCommand struct {
	identity executableIdentity
	file     *os.File
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

// measureCustomerCommand resolves the command and its first operand afresh
// and digests both. The command's file is opened once and digested from that
// descriptor, which the caller closes.
func measureCustomerCommand(command []string, workspace string) (*measuredCommand, error) {
	path, err := resolveCustomerWord(command[0], workspace, true)
	if err != nil {
		return nil, fmt.Errorf("server command could not be resolved: %v", err)
	}
	file, digest, err := openDigest(path)
	if err != nil {
		return nil, err
	}
	m := &measuredCommand{identity: executableIdentity{Digest: digest, Path: path}, file: file}
	for _, word := range command[1:] {
		if strings.HasPrefix(word, "-") {
			continue
		}
		// The first operand, when it names a regular file, is the script.
		if script, err := resolveCustomerWord(word, workspace, false); err == nil {
			if info, err := os.Stat(script); err == nil && info.Mode().IsRegular() {
				f, digest, err := openDigest(script)
				if err != nil {
					file.Close()
					return nil, err
				}
				f.Close()
				m.identity.Script = &fileIdentity{Digest: digest, Path: script}
			}
		}
		break
	}
	return m, nil
}

// openDigest opens a regular file and digests it from the open descriptor.
func openDigest(path string) (*os.File, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, "", fmt.Errorf("server executable could not be read for its digest: %w", err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, "", fmt.Errorf("server executable %s is not a regular file", path)
	}
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		file.Close()
		return nil, "", fmt.Errorf("server executable could not be read for its digest: %w", err)
	}
	return file, "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
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
	return nil
}

// recheckBeforeStart digests again, immediately before the start, each file
// that is not executed through the descriptor it was digested from: the
// script always (its interpreter opens it by path), and the command when the
// backend executes it by path. A change in between refuses the start.
func recheckBeforeStart(m *measuredCommand, executesDescriptor bool) error {
	if !executesDescriptor {
		f, digest, err := openDigest(m.identity.Path)
		if err != nil {
			return err
		}
		f.Close()
		if digest != m.identity.Digest {
			return errors.New("mcp-executable-changed: the command's file changed between its digest and its start")
		}
	}
	if s := m.identity.Script; s != nil {
		f, digest, err := openDigest(s.Path)
		if err != nil {
			return err
		}
		f.Close()
		if digest != s.Digest {
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
