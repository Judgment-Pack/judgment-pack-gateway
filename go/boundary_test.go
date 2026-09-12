package main

import (
	"bufio"
	"go/build"
	goparser "go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The process boundary is the security claim (ADR-0001). This module holds the
// signing seed, so it imports the standard library and nothing else: no
// third-party module, no cgo, and never the adapters module that lives beside
// it in this repository. CI has checked "no third-party modules" from outside
// since before the adapters module existed; that check lets a same-repository
// module through, because its import path looks like a standard-library one.
// This test closes that gap and makes `go test ./...` fail on the first
// crossing, on a developer's machine, before a pull request exists.

// refuseImport reports why an import path is refused in the core, or "" when
// it is a standard-library package. A path is standard-library when its first
// element carries no dot and a directory of that name exists under GOROOT/src.
func refuseImport(goroot, path string) string {
	switch {
	case path == "C":
		return "cgo import; the signer is pure Go"
	case path == "adapters" || strings.HasPrefix(path, "adapters/"):
		return "imports the adapters module; nothing that holds platform credentials may be linked into the signer"
	case path == "gateway" || strings.HasPrefix(path, "gateway/"):
		return "imports this module by its module path; the core is one package and reaches nothing through its own name"
	}
	first := path
	if i := strings.IndexByte(path, '/'); i >= 0 {
		first = path[:i]
	}
	if strings.Contains(first, ".") {
		return "third-party import; the core takes no dependency"
	}
	info, err := os.Stat(filepath.Join(goroot, "src", filepath.FromSlash(path)))
	if err != nil || !info.IsDir() {
		return "not a standard-library package"
	}
	return ""
}

func TestRefuseImportHasTeeth(t *testing.T) {
	goroot := build.Default.GOROOT
	cases := map[string]bool{
		"crypto/ed25519":   false,
		"net/http":         false,
		"os/exec":          false,
		"C":                true,
		"adapters":         true,
		"adapters/airbyte": true,
		"gateway":          true,
		"github.com/x/y":   true,
		"golang.org/x/net": true,
		"notastdlibpkg":    true, // no dot, but not under GOROOT/src either
	}
	for path, refused := range cases {
		got := refuseImport(goroot, path) != ""
		if got != refused {
			t.Errorf("refuseImport(%q): refused=%v, want %v", path, got, refused)
		}
	}
}

func TestCoreImportsOnlyTheStandardLibrary(t *testing.T) {
	goroot := build.Default.GOROOT
	if goroot == "" {
		t.Fatal("GOROOT is empty; cannot tell a standard-library package from anything else")
	}
	fset := token.NewFileSet()
	var checked int
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); path != "." && (strings.HasPrefix(name, ".") || name == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := goparser.ParseFile(fset, path, nil, goparser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return err
			}
			checked++
			if why := refuseImport(goroot, p); why != "" {
				t.Errorf("%s imports %q: %s", path, p, why)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("walked no imports; the check is not running over the module it claims to guard")
	}
}

// go.mod states the module and the language version and nothing else. A
// `require` is a dependency, a `replace` is how a same-repository module would
// be made importable, and an `exclude` only exists to manage requirements this
// module does not have.
func TestGoModDeclaresNoDependencies(t *testing.T) {
	f, err := os.Open("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "//") {
			continue
		}
		field := text
		if i := strings.IndexByte(text, ' '); i >= 0 {
			field = text[:i]
		}
		switch field {
		case "module", "go", "toolchain":
			continue
		}
		t.Errorf("go.mod:%d: %q — the core declares no dependency, replacement, or exclusion", line, text)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
}
