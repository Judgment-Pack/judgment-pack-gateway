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

func TestFindNamesBundleOrSystemByAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	saved := bundle
	t.Cleanup(func() { bundle = saved })
	bundle = func() string { return dir }
	t.Setenv("PATH", t.TempDir())
	if tool := Find("pdftoppm"); tool.Path != "/usr/bin/pdftoppm" {
		t.Fatal("a program the bundle lacks is not the system's", tool.Path)
	} else {
		for _, kv := range tool.Env {
			if strings.HasPrefix(kv, "LD_LIBRARY_PATH="+dir) || strings.HasPrefix(kv, "TESSDATA_PREFIX="+dir) {
				t.Fatal("the bundle's libraries reach a system program")
			}
		}
	}
	bin := filepath.Join(dir, "usr", "bin")
	os.MkdirAll(bin, 0700)
	standIn(t, bin, "tesseract", "exit 0\n")
	tool := Find("tesseract")
	if tool.Path != filepath.Join(bin, "tesseract") {
		t.Fatal("the bundle's program is not used", tool.Path)
	}
	joined := strings.Join(tool.Env, "\n")
	if !strings.Contains(joined, "LD_LIBRARY_PATH="+filepath.Join(dir, "usr", "lib")) || !strings.Contains(joined, "TESSDATA_PREFIX="+filepath.Join(dir, "usr", "share")) {
		t.Fatal("the bundle's program runs without its libraries")
	}
	// A bundle entry that is not an executable file is not used.
	os.WriteFile(filepath.Join(bin, "pdftoppm"), []byte("x"), 0600)
	if Find("pdftoppm").Path != "/usr/bin/pdftoppm" {
		t.Fatal("a non-executable bundle entry was used")
	}
	bundle = func() string { return "" }
	if Find("tesseract").Path != "/usr/bin/tesseract" {
		t.Fatal("no bundle, and not the system's program")
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
	renderer = func() Tool {
		return Tool{standIn(t, dir, "render", "echo \"$@\" > "+args+"\n/bin/cat >/dev/null\nprintf '\\211PNG\\r\\n\\032\\nimage'\n"), nil}
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
	renderer = func() Tool { return Tool{standIn(t, dir, "text", "printf 'not an image'\n"), nil} }
	if _, err = Page(context.Background(), []byte("%PDF"), 1, 1024); err == nil {
		t.Fatal("output that is not a PNG was taken as a page image")
	}
}
