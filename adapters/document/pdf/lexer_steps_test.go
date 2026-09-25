package pdf

import (
	"bytes"
	"go/ast"
	"go/build"
	"go/constant"
	"go/importer"
	goparser "go/parser"
	"go/printer"
	gotoken "go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Every step back a lexer makes is made through back, so that what it reads
// again is counted toward the reading of the deadline. A lexer's position
// set anywhere else could step it back without back, and neither due nor
// lexTrace would count what it read again, so the reader's sources are read
// for every write of it: an assignment of any kind, an increment or
// decrement, or its address taken, through whatever expression names a
// lexer's position -- found by the type of what is written, and not by how
// it is spelled. The writes allowed are the ones that only move a lexer
// forward: back's own, a token's end where the lexer's reading of it stands,
// an increment, an addition of a length or a constant, and an inline image's
// end. A lexer is built by newLexer alone, a whole lexer is never assigned,
// and a parser's lexer is never replaced by another at another position.
// TestTheLexerProbesHold counts what a lexer advances over apart from any of
// this.
func TestALexerStepsBackOnlyThroughBack(t *testing.T) {
	fset := gotoken.NewFileSet()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		if ok, err := build.Default.MatchFile(".", name); err != nil || !ok {
			continue
		}
		f, err := goparser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	info := &types.Info{Selections: map[*ast.SelectorExpr]*types.Selection{}, Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{}}
	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
	pkg, err := conf.Check("pdf", fset, files, info)
	if err != nil {
		t.Fatal(err)
	}
	lexerType := pkg.Scope().Lookup("lexer").Type()
	var pos types.Object
	fields := lexerType.Underlying().(*types.Struct)
	for i := 0; i < fields.NumFields(); i++ {
		if fields.Field(i).Name() == "pos" {
			pos = fields.Field(i)
		}
	}
	isPos := func(e ast.Expr) bool {
		sel, ok := ast.Unparen(e).(*ast.SelectorExpr)
		return ok && info.Selections[sel] != nil && info.Selections[sel].Obj() == pos
	}
	source := func(n ast.Node) string {
		var b strings.Builder
		printer.Fprint(&b, fset, n)
		return b.String()
	}
	forward := func(fn string, tok gotoken.Token, rhs ast.Expr) bool {
		switch tok {
		case gotoken.ADD_ASSIGN:
			if tv := info.Types[rhs]; tv.Value != nil {
				return constant.Sign(tv.Value) >= 0
			}
			call, ok := rhs.(*ast.CallExpr)
			if !ok {
				return false
			}
			id, ok := call.Fun.(*ast.Ident)
			_, builtin := info.Uses[id].(*types.Builtin)
			return ok && builtin && id.Name == "len"
		case gotoken.ASSIGN:
			id, ok := rhs.(*ast.Ident)
			if !ok {
				return false
			}
			return fn == "back" && id.Name == "to" || (fn == "next" || fn == "number") && id.Name == "end" || fn == "skipInlineImage" && id.Name == "at"
		}
		return false
	}
	writes := 0
	for _, f := range files {
		var fn string
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncDecl:
				fn = x.Name.Name
			case *ast.AssignStmt:
				for i, lhs := range x.Lhs {
					if tv, ok := info.Types[lhs]; ok && x.Tok != gotoken.DEFINE && (types.Identical(tv.Type, lexerType) || types.Identical(tv.Type, types.NewPointer(lexerType))) {
						t.Errorf("%s: %s assigns a lexer in %s", fset.Position(x.Pos()), source(x), fn)
					}
					if !isPos(lhs) {
						continue
					}
					writes++
					rhs := x.Rhs[min(i, len(x.Rhs)-1)]
					if !forward(fn, x.Tok, rhs) {
						t.Errorf("%s: %s sets a lexer's position in %s without back", fset.Position(x.Pos()), source(x), fn)
					}
				}
			case *ast.IncDecStmt:
				if isPos(x.X) {
					writes++
					if x.Tok != gotoken.INC {
						t.Errorf("%s: %s steps a lexer back without back", fset.Position(x.Pos()), source(x))
					}
				}
			case *ast.UnaryExpr:
				if x.Op == gotoken.AND && isPos(x.X) {
					t.Errorf("%s: %s takes the address of a lexer's position", fset.Position(x.Pos()), source(x))
				}
			case *ast.CompositeLit:
				if tv, ok := info.Types[x]; ok && types.Identical(tv.Type, lexerType) && fn != "newLexer" {
					t.Errorf("%s: a lexer is built in %s and not by newLexer", fset.Position(x.Pos()), fn)
				}
			}
			return true
		})
	}
	t.Logf("%d writes of a lexer's position, every one forward or back's own", writes)
	if writes == 0 {
		t.Fatal("no write of a lexer's position was found")
	}
}

// The tests of the build made with the pdflexprobe tag -- where every byte a
// lexer loads is counted where it is loaded, apart from due, lexTrace and the
// sources' spelling -- run from here, in a build of their own, so that the
// ordinary test run holds the lexer to them. See lexprobe_test.go.
func TestTheLexerProbesHold(t *testing.T) {
	if lexProbed {
		t.Skip("this is the probe build")
	}
	if testing.Short() {
		t.Skip("the probe build is a build of its own")
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		goTool = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	cmd := exec.Command(goTool, "test", "-tags", "pdflexprobe", "-count=1", "-run", "^TestLexerProbe", ".")
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the probe build's tests: %v\n%s", err, out)
	}
	t.Logf("%s", bytes.TrimSpace(out))
}
