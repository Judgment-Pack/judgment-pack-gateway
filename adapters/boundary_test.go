package adapters

import (
	"bufio"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The process boundary is the security claim (ADR-0001). The core module holds
// the signing seed and nothing else; this module holds platform credentials and
// never the seed. That only means something if the two cannot be linked into
// one process, so this module must never import the core module, and nothing
// may make such an import resolve under another name: no `replace` in go.mod,
// no workspace file, no nested module, no vendor directory. CI checks the
// resolved provenance of every dependency from outside; these tests make
// `go test ./...` fail on the first crossing, on a developer's machine, before
// a pull request exists.
//
// They are import guards. They prove what this module links, not what an
// adapter's process can read; the process model in docs/design/engine-image.md
// is what the second claim rests on.

// crossesBoundary reports why an import path is refused in this module, or ""
// when it is allowed. Third-party modules are allowed here — this module may
// grow dependencies the core never will — so the refusals are the core module
// itself, under any spelling the Go toolchain would resolve, and the two ways
// of linking foreign code at run time.
func crossesBoundary(path string) string {
	switch {
	case path == "gateway" || strings.HasPrefix(path, "gateway/"):
		return "imports the core module; the signer must never be linkable into an adapter"
	case path == "C":
		return "cgo import; an adapter that links C code cannot be audited as Go"
	case path == "plugin":
		return "the plugin package loads foreign code at run time; an adapter links what it declares"
	}
	return ""
}

func TestBoundaryClassifierHasTeeth(t *testing.T) {
	cases := map[string]bool{
		"gateway":            true,
		"gateway/internal/x": true,
		"C":                  true,
		"plugin":             true,
		"gatewayx":           false, // a different module, not a spelling of ours
		"net/http":           false,
		"encoding/json":      false,
		"github.com/x/y":     false, // permitted here, refused in the core
	}
	for path, refused := range cases {
		got := crossesBoundary(path) != ""
		if got != refused {
			t.Errorf("crossesBoundary(%q): refused=%v, want %v", path, got, refused)
		}
	}
}

// TestNoImportCrossesIntoTheCore scans every .go file under the module. It
// skips nothing but .git: a file under testdata or a dot directory is not
// built by ./..., but it can be built by naming its path, so it is scanned too.
func TestNoImportCrossesIntoTheCore(t *testing.T) {
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
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return err
			}
			checked++
			if why := crossesBoundary(p); why != "" {
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

func TestGoModCarriesNoReplace(t *testing.T) {
	f, err := os.Open("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(text, "replace") {
			t.Errorf("go.mod:%d: %q — a replace directive is how a cross-module import would resolve; none is allowed", line, text)
		}
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
