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
// third-party module, no cgo, no plugin loading, and never the adapters module
// that lives beside it in this repository. CI has checked "no third-party
// modules" from outside since before the adapters module existed; that check
// lets a same-repository module through, because its import path looks like a
// standard-library one. These tests close that gap on a developer's machine,
// before a pull request exists.
//
// They are import guards. They prove what the core links, not what the
// signer's process can read; the process model in docs/design/engine-image.md
// is what the second claim rests on, and CI's resolved-provenance check
// (`go list -deps -f '{{.Standard}}'`) is the authoritative form of the first.

// refuseImport reports why an import path is refused in the core, or "" when
// it is a standard-library package. A path is standard-library when its first
// element carries no dot, no element of it is "testdata", and a directory of
// that name under GOROOT/src holds at least one non-test Go file — a directory
// that merely exists there, such as net/http/testdata, is not a package.
func refuseImport(goroot, path string) string {
	switch {
	case path == "C":
		return "cgo import; the signer is pure Go"
	case path == "plugin":
		return "the plugin package loads foreign code into this process; the signer links nothing at run time"
	case path == "adapters" || strings.HasPrefix(path, "adapters/"):
		return "imports the adapters module; nothing that holds platform credentials may be linked into the signer"
	case path == "gateway" || strings.HasPrefix(path, "gateway/"):
		return "imports this module by its module path; the core is one package and reaches nothing through its own name"
	}
	for _, elem := range strings.Split(path, "/") {
		if elem == "testdata" {
			return "a testdata path is never a package"
		}
	}
	first := path
	if i := strings.IndexByte(path, '/'); i >= 0 {
		first = path[:i]
	}
	if strings.Contains(first, ".") {
		return "third-party import; the core takes no dependency"
	}
	dir := filepath.Join(goroot, "src", filepath.FromSlash(path))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "not a standard-library package"
	}
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() && strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			return ""
		}
	}
	return "not a standard-library package: the directory holds no Go source"
}

func TestRefuseImportHasTeeth(t *testing.T) {
	goroot := build.Default.GOROOT
	cases := map[string]bool{
		"crypto/ed25519":    false,
		"net/http":          false,
		"os/exec":           false,
		"C":                 true,
		"plugin":            true,
		"adapters":          true,
		"adapters/airbyte":  true,
		"gateway":           true,
		"github.com/x/y":    true,
		"golang.org/x/net":  true,
		"notastdlibpkg":     true, // no dot, but not under GOROOT/src either
		"net/http/testdata": true, // a directory under GOROOT/src that is not a package
		"cmd":               true, // exists under GOROOT/src, holds no Go source of its own
	}
	for path, refused := range cases {
		got := refuseImport(goroot, path) != ""
		if got != refused {
			t.Errorf("refuseImport(%q): refused=%v, want %v", path, got, refused)
		}
	}
}

// walkModuleGoFiles visits every .go file under the module directory. It skips
// nothing but .git: a file under testdata or a dot directory is not built by
// ./..., but it can be built by naming its path, so it is scanned too.
func walkModuleGoFiles(t *testing.T, visit func(path string, imports []string)) {
	t.Helper()
	fset := token.NewFileSet()
	var checked int
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
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
		var imports []string
		for _, imp := range f.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return err
			}
			imports = append(imports, p)
		}
		checked += len(imports)
		visit(path, imports)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("walked no imports; the check is not running over the module it claims to guard")
	}
}

func TestCoreImportsOnlyTheStandardLibrary(t *testing.T) {
	goroot := build.Default.GOROOT
	if goroot == "" {
		t.Fatal("GOROOT is empty; cannot tell a standard-library package from anything else")
	}
	walkModuleGoFiles(t, func(path string, imports []string) {
		for _, p := range imports {
			if why := refuseImport(goroot, p); why != "" {
				t.Errorf("%s imports %q: %s", path, p, why)
			}
		}
	})
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

// A workspace file, a nested module, or a vendor directory is a way to make an
// import resolve somewhere the import path does not say. None may exist: not
// in this module, and not at the repository root above it.
func TestNoWorkspaceNestedModuleOrVendor(t *testing.T) {
	for _, p := range []string{"go.work", "../go.work", "vendor"} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s exists; it can redirect where an import resolves and is refused", p)
		}
	}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			if d.Name() == "vendor" {
				t.Errorf("%s: a vendor directory is refused", path)
			}
			return nil
		}
		if path != "go.mod" && d.Name() == "go.mod" {
			t.Errorf("%s: a nested module escapes ./... and is refused", path)
		}
		if d.Name() == "go.work" {
			t.Errorf("%s: a workspace file is refused", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
