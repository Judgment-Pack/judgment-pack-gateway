// Package ocrrender names the Poppler and Tesseract programs the OCR workers
// run and runs them: each by absolute path, from the OCR tools bundled beside
// the running executable when the bundle carries that program, or else from
// /usr/bin, never looked up on PATH. A program is started without a shell,
// its input is given on stdin and its output read from a bounded pipe, so no
// document or page image is written to disk by these workers, and a program
// that writes past its bound or outlives its context is ended.
package ocrrender

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Tool is one program: its absolute path and the environment it runs with.
type Tool struct {
	Path string
	Env  []string
}

// bundle is the directory of OCR tools beside the running executable, or ""
// when the executable's own path is not known as an absolute path. Tests
// replace it.
var bundle = func() string {
	exe, err := os.Executable()
	if err != nil || !filepath.IsAbs(exe) {
		return ""
	}
	return filepath.Join(filepath.Dir(exe), "ocr-tools")
}

// BundleDir is the directory of OCR tools beside the running executable, or
// "" when that executable's path is not known.
func BundleDir() string { return bundle() }

func runnable(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0111 != 0
}

// systemDir is where a program the bundle does not carry is taken from.
// Tests replace it.
var systemDir = "/usr/bin"

// ErrNoTool is a program found in neither place.
var ErrNoTool = errors.New("the program is in neither the OCR tools bundle nor /usr/bin")

// Find names the program called name, by its path with every symlink
// resolved: the bundle's copy when, so resolved, it is a regular executable
// file inside the bundle, run with the bundle's libraries and language data;
// otherwise the system's, held to /usr/bin the same way and run with the
// caller's environment. A candidate that resolves anywhere else is not used,
// and the bundle's libraries are given only to a program established inside
// the bundle.
func Find(name string) (Tool, error) {
	if dir := bundle(); dir != "" {
		if path, ok := within(dir, filepath.Join(dir, "usr", "bin", name)); ok {
			triple := "x86_64-linux-gnu"
			if runtime.GOARCH == "arm64" {
				triple = "aarch64-linux-gnu"
			}
			env := append(os.Environ(),
				"LD_LIBRARY_PATH="+filepath.Join(dir, "usr", "lib", triple),
				"TESSDATA_PREFIX="+filepath.Join(dir, "usr", "share", "tesseract-ocr", "4.00", "tessdata"))
			return Tool{path, env}, nil
		}
	}
	if path, ok := within(systemDir, filepath.Join(systemDir, name)); ok {
		return Tool{path, os.Environ()}, nil
	}
	return Tool{}, ErrNoTool
}

// within resolves candidate and answers its resolved path when that is a
// regular executable file inside root, itself resolved.
func within(root, candidate string) (string, bool) {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", false
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(realRoot, resolved)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") || filepath.IsAbs(rel) || !runnable(resolved) {
		return "", false
	}
	return resolved, true
}

// Available reports whether Find names the program now. It is a check made
// now, not a promise about the next run.
func Available(name string) bool {
	_, err := Find(name)
	return err == nil
}

// ErrBound is a program that wrote past its output bound, or whose output
// could not be read to its end before its context ended; it was ended.
var ErrBound = errors.New("the program's output passed its bound or was cut off; the program was ended")

// Run starts t with args, gives it input on stdin and reads at most limit
// bytes of its stdout. Its stderr is discarded.
func Run(ctx context.Context, t Tool, args []string, input []byte, limit int64) ([]byte, error) {
	cmd := exec.CommandContext(ctx, t.Path, args...)
	cmd.Env = t.Env
	cmd.Stdin = bytes.NewReader(input)
	cmd.WaitDelay = time.Second
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = pipe.Close() })
	defer stop()
	data, err := io.ReadAll(io.LimitReader(pipe, limit+1))
	if err != nil || int64(len(data)) > limit {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, ErrBound
	}
	if err = cmd.Wait(); err != nil {
		return nil, err
	}
	return data, nil
}

// renderer is the Poppler program a page is rendered with. Tests replace it.
var renderer = func() (Tool, error) { return Find("pdftoppm") }

// MaxScale is the longest side, in pixels, a page is rendered to.
const MaxScale = 2500

// Page renders page number of pdf as one PNG whose longest side is at most
// MaxScale pixels, holding the image to limit bytes.
func Page(ctx context.Context, pdf []byte, number int, limit int64) ([]byte, error) {
	n := strconv.Itoa(number)
	tool, err := renderer()
	if err != nil {
		return nil, err
	}
	out, err := Run(ctx, tool, []string{"-f", n, "-l", n, "-scale-to", strconv.Itoa(MaxScale), "-singlefile", "-png", "-"}, pdf, limit)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(out, []byte("\x89PNG\r\n\x1a\n")) {
		return nil, errors.New("page rendering did not give a PNG image")
	}
	return out, nil
}
