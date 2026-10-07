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

// Find names the program called name. The bundle's copy runs with the
// bundle's libraries and language data; the system's runs with the caller's
// environment, so the bundle's libraries never reach a system program.
func Find(name string) Tool {
	if dir := bundle(); dir != "" {
		path := filepath.Join(dir, "usr", "bin", name)
		if runnable(path) {
			triple := "x86_64-linux-gnu"
			if runtime.GOARCH == "arm64" {
				triple = "aarch64-linux-gnu"
			}
			env := append(os.Environ(),
				"LD_LIBRARY_PATH="+filepath.Join(dir, "usr", "lib", triple),
				"TESSDATA_PREFIX="+filepath.Join(dir, "usr", "share", "tesseract-ocr", "4.00", "tessdata"))
			return Tool{path, env}
		}
	}
	return Tool{filepath.Join("/usr/bin", name), os.Environ()}
}

// Available reports whether the program Find names is a regular executable
// file now. It is a check made now, not a promise about the next run.
func Available(name string) bool { return runnable(Find(name).Path) }

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
var renderer = func() Tool { return Find("pdftoppm") }

// MaxScale is the longest side, in pixels, a page is rendered to.
const MaxScale = 2500

// Page renders page number of pdf as one PNG whose longest side is at most
// MaxScale pixels, holding the image to limit bytes.
func Page(ctx context.Context, pdf []byte, number int, limit int64) ([]byte, error) {
	n := strconv.Itoa(number)
	out, err := Run(ctx, renderer(), []string{"-f", n, "-l", n, "-scale-to", strconv.Itoa(MaxScale), "-singlefile", "-png", "-"}, pdf, limit)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(out, []byte("\x89PNG\r\n\x1a\n")) {
		return nil, errors.New("page rendering did not give a PNG image")
	}
	return out, nil
}
