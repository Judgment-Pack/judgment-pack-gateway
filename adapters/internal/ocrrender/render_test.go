//go:build linux || darwin

package ocrrender

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// standIn writes a shell script that stands in for a program. No installed
// OCR program is run by these tests.
func standIn(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

// gone reports whether the process whose PID the stand-in wrote has ended.
func gone(t *testing.T, pidFile string) bool {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		raw, err := os.ReadFile(pidFile)
		if err != nil {
			t.Fatal("the stand-in did not start", err)
		}
		pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
		if pid > 0 && syscall.Kill(pid, 0) != nil {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// resolved is path with every symlink resolved, as Find names a program.
func resolved(t *testing.T, path string) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return real
}

func TestFindNamesBundleOrSystemByAbsolutePath(t *testing.T) {
	root := t.TempDir()
	dir, system, elsewhere := filepath.Join(root, "ocr-tools"), filepath.Join(root, "usr-bin"), filepath.Join(root, "elsewhere")
	bin := filepath.Join(dir, "usr", "bin")
	for _, d := range []string{bin, system, elsewhere} {
		os.MkdirAll(d, 0700)
	}
	savedBundle, savedSystem := bundle, systemDir
	t.Cleanup(func() { bundle, systemDir = savedBundle, savedSystem })
	bundle, systemDir = func() string { return dir }, system
	t.Setenv("PATH", t.TempDir())
	if _, err := Find("pdftoppm"); err != ErrNoTool {
		t.Fatal("a program in neither place was named", err)
	}
	systemCopy := standIn(t, system, "pdftoppm", "exit 0\n")
	systemReal := resolved(t, systemCopy)
	if tool, err := Find("pdftoppm"); err != nil || tool.Path != systemReal {
		t.Fatal("a program the bundle lacks is not the system's", tool.Path, err)
	} else {
		for _, kv := range tool.Env {
			if strings.HasPrefix(kv, "LD_LIBRARY_PATH="+dir) || strings.HasPrefix(kv, "TESSDATA_PREFIX="+dir) {
				t.Fatal("the bundle's libraries reach a system program")
			}
		}
	}
	bundled := resolved(t, standIn(t, bin, "tesseract", "exit 0\n"))
	tool, err := Find("tesseract")
	if err != nil || tool.Path != bundled {
		t.Fatal("the bundle's program is not used", tool.Path, err)
	}
	joined := strings.Join(tool.Env, "\n")
	if !strings.Contains(joined, "LD_LIBRARY_PATH="+filepath.Join(dir, "usr", "lib")) || !strings.Contains(joined, "TESSDATA_PREFIX="+filepath.Join(dir, "usr", "share")) {
		t.Fatal("the bundle's program runs without its libraries")
	}
	// A bundle entry that is not an executable file is not used.
	os.WriteFile(filepath.Join(bin, "pdftoppm"), []byte("x"), 0600)
	if tool, _ := Find("pdftoppm"); tool.Path != systemReal {
		t.Fatal("a non-executable bundle entry was used")
	}
	// A symlink, in the bundle or in the system's place, to a program
	// elsewhere is never named, and never given the bundle's libraries.
	outside := standIn(t, elsewhere, "renderer", "exit 0\n")
	os.Remove(filepath.Join(bin, "pdftoppm"))
	os.Symlink(outside, filepath.Join(bin, "pdftoppm"))
	if tool, err := Find("pdftoppm"); err != nil || tool.Path != systemReal {
		t.Fatal("a bundle link to a program elsewhere was named", tool.Path, err)
	}
	os.Remove(systemCopy)
	os.Symlink(outside, systemCopy)
	if tool, err := Find("pdftoppm"); err != ErrNoTool || tool.Path != "" {
		t.Fatal("a link to a program elsewhere was named", tool.Path, err)
	}
	if Available("pdftoppm") {
		t.Fatal("a program named nowhere is available")
	}
	// A link that stays inside the bundle is the program it names.
	os.Remove(filepath.Join(bin, "pdftoppm"))
	os.Symlink(bundled, filepath.Join(bin, "pdftoppm"))
	if tool, err := Find("pdftoppm"); err != nil || tool.Path != bundled {
		t.Fatal("a link inside the bundle was not followed to its program", tool.Path, err)
	}
	bundle = func() string { return "" }
	if tool, err := Find("tesseract"); err != ErrNoTool || tool.Path != "" {
		t.Fatal("no bundle and no system program, and a program was named")
	}
}

func TestRunEndsAProgramPastItsBound(t *testing.T) {
	dir := t.TempDir()
	pid := filepath.Join(dir, "pid")
	tool := Tool{standIn(t, dir, "flood", "echo $$ > "+pid+"\nwhile :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; done\n"), nil}
	start := time.Now()
	if _, err := Run(context.Background(), tool, nil, nil, 4096); err != ErrBound {
		t.Fatal("output past the bound was taken", err)
	}
	if !gone(t, pid) || time.Since(start) > 5*time.Second {
		t.Fatal("a program past its bound was not ended")
	}
	exact := Tool{standIn(t, dir, "exact", "printf abcd\n"), nil}
	if out, err := Run(context.Background(), exact, nil, nil, 4); err != nil || string(out) != "abcd" {
		t.Fatal("output at the bound refused", err)
	}
}

func TestRunEndsAProgramAtItsDeadline(t *testing.T) {
	dir := t.TempDir()
	pid := filepath.Join(dir, "pid")
	tool := Tool{standIn(t, dir, "hang", "echo $$ > "+pid+"\nwhile :; do :; done\n"), nil}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := Run(ctx, tool, nil, nil, 4096); err == nil {
		t.Fatal("a program past its deadline answered")
	}
	if !gone(t, pid) || time.Since(start) > 5*time.Second {
		t.Fatal("a program past its deadline was not ended")
	}
}

func TestRunGivesInputOnStdinAndNoShell(t *testing.T) {
	dir := t.TempDir()
	tool := Tool{standIn(t, dir, "echo-args", "printf '%s|' \"$@\"\n/bin/cat\n"), nil}
	out, err := Run(context.Background(), tool, []string{"a b", "$(id)", ";x"}, []byte("PDF"), 1024)
	if err != nil || string(out) != "a b|$(id)|;x|PDF" {
		t.Fatalf("%q %v", out, err)
	}
}

func TestPageHoldsTheImageToItsBoundAndForm(t *testing.T) {
	dir := t.TempDir()
	saved := renderer
	t.Cleanup(func() { renderer = saved })
	args := filepath.Join(dir, "args")
	renderer = func() (Tool, error) {
		return Tool{standIn(t, dir, "render", "echo \"$@\" > "+args+"\n/bin/cat >/dev/null\nprintf '\\211PNG\\r\\n\\032\\nimage'\n"), nil}, nil
	}
	out, err := Page(context.Background(), []byte("%PDF"), 3, 1024)
	if err != nil || !bytes.HasPrefix(out, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(args); strings.TrimSpace(string(raw)) != "-f 3 -l 3 -scale-to 2500 -singlefile -png -" {
		t.Fatalf("rendered with %q", raw)
	}
	if _, err = Page(context.Background(), []byte("%PDF"), 3, 8); err != ErrBound {
		t.Fatal("an image past its bound was taken", err)
	}
	renderer = func() (Tool, error) { return Tool{standIn(t, dir, "text", "printf 'not an image'\n"), nil}, nil }
	if _, err = Page(context.Background(), []byte("%PDF"), 1, 1024); err == nil {
		t.Fatal("output that is not a PNG was taken as a page image")
	}
}
