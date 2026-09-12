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
// one process, so this module must never import the core module, and its
// go.mod must never carry a `replace` that would make such an import resolve.
// CI checks the same from outside; this test makes `go test ./...` fail on the
// first crossing, on a developer's machine, before a pull request exists.

// crossesBoundary reports why an import path is refused in this module, or ""
// when it is allowed. Third-party modules are allowed here — this module may
// grow dependencies the core never will — so the only refusal is the core
// module itself, under any spelling the Go toolchain would resolve.
func crossesBoundary(path string) string {
	switch {
	case path == "gateway" || strings.HasPrefix(path, "gateway/"):
		return "imports the core module; the signer must never be linkable into an adapter"
	case path == "C":
		return "cgo import; an adapter that links C code cannot be audited as Go"
	}
	return ""
}

func TestBoundaryClassifierHasTeeth(t *testing.T) {
	cases := map[string]bool{
		"gateway":            true,
		"gateway/internal/x": true,
		"C":                  true,
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

func TestNoImportCrossesIntoTheCore(t *testing.T) {
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
