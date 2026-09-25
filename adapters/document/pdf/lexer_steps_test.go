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
// lexTrace would count what it read again; and a copy of a lexer carries a
// position and a due of its own, so that a parser handed one, or a method
// that works on one, reads again what the lexer it was copied from has read
// with neither counting it. So the reader's sources are read, with their
// types checked, for every write of a lexer's position -- an assignment of
// any kind, an increment or decrement, or its address taken, through
// whatever expression names it -- and for every lexer that is not the one
// newLexer made: a value of type lexer declared anywhere, a receiver, a
// parameter or a field included, an expression of that type that is not
// the lexer itself having a field or method taken from it, a lexer built or
// allocated anywhere but in newLexer, a method of a lexer with a value
// receiver, and a parser whose lexer, or which whole, is replaced after it
// is built. A lexer pointer is assigned only where it is first made: a
// variable is made from newLexer and never assigned again, a parameter or a
// receiver never assigned at all, and a parser's lexer is given where the
// parser is built, from newLexer or from a lexer made so -- so that no
// lexer is made again in the place of one at work, with a due of its own.
// No value is converted to or from a type the lexer is, or a pointer to
// one, no type is declared that is a lexer under another name, and no
// generic function or type is instantiated with a lexer, a pointer to one or
// such a type, so that a lexer is never the value of a type parameter. The
// writes of a position allowed are the ones that only move a
// lexer forward: back's own, a token's end where the lexer's reading of it
// stands, an increment, an addition of a length or a constant, and an
// inline image's end, each known by the function it is written in as the
// type checker knows it, and not by that function's name.
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
	info := &types.Info{Selections: map[*ast.SelectorExpr]*types.Selection{}, Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}, Instances: map[*ast.Ident]types.Instance{}}
	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
	pkg, err := conf.Check("pdf", fset, files, info)
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(typ types.Type, name string) types.Object {
		obj, _, _ := types.LookupFieldOrMethod(typ, true, pkg, name)
		if obj == nil {
			t.Fatalf("%s has no %s", typ, name)
		}
		return obj
	}
	lexerType := pkg.Scope().Lookup("lexer").Type()
	parserType := pkg.Scope().Lookup("parser").Type()
	lexerPointer := types.NewPointer(lexerType)
	pos, lexOf := lookup(lexerType, "pos"), lookup(parserType, "lex")
	back, next, number := lookup(lexerPointer, "back"), lookup(lexerPointer, "next"), lookup(lexerPointer, "number")
	skipInlineImage := lookup(types.NewPointer(pkg.Scope().Lookup("interp").Type()), "skipInlineImage")
	construct := pkg.Scope().Lookup("newLexer")
	isLexer := func(typ types.Type) bool { return types.Identical(typ, lexerType) }
	// lexerLike reports whether typ is a lexer under any name, or a pointer
	// to one.
	lexerLike := func(typ types.Type) bool {
		if p, ok := typ.Underlying().(*types.Pointer); ok {
			typ = p.Elem()
		}
		return types.Identical(typ.Underlying(), lexerType.Underlying())
	}
	isLexerPointer := func(typ types.Type) bool { return typ != nil && types.Identical(typ, lexerPointer) }
	within, reserving := lookup(lexerPointer, "within"), lookup(lexerPointer, "reserving")
	// made reports whether e is a lexer made by newLexer, given an allowance
	// or not.
	var made func(e ast.Expr) bool
	made = func(e ast.Expr) bool {
		call, ok := ast.Unparen(e).(*ast.CallExpr)
		if !ok {
			return false
		}
		switch f := ast.Unparen(call.Fun).(type) {
		case *ast.Ident:
			return info.Uses[f] == construct
		case *ast.SelectorExpr:
			sel := info.Selections[f]
			return sel != nil && (sel.Obj() == within || sel.Obj() == reserving) && made(f.X)
		}
		return false
	}
	// held reports whether e names a lexer already made: a variable, a
	// parameter or a field that holds one.
	held := func(e ast.Expr) bool {
		switch x := ast.Unparen(e).(type) {
		case *ast.Ident:
			_, isVar := info.Uses[x].(*types.Var)
			return isVar
		case *ast.SelectorExpr:
			sel := info.Selections[x]
			return sel != nil && sel.Kind() == types.FieldVal
		}
		return false
	}
	isField := func(e ast.Expr, field types.Object) bool {
		sel, ok := ast.Unparen(e).(*ast.SelectorExpr)
		return ok && info.Selections[sel] != nil && info.Selections[sel].Obj() == field
	}
	source := func(n ast.Node) string {
		var b strings.Builder
		printer.Fprint(&b, fset, n)
		return b.String()
	}
	named := lexerType.(*types.Named)
	for i := 0; i < named.NumMethods(); i++ {
		m := named.Method(i)
		if _, pointer := m.Type().(*types.Signature).Recv().Type().(*types.Pointer); !pointer {
			t.Errorf("%s: the lexer's method %s has a value receiver, and works on a copy", fset.Position(m.Pos()), m.Name())
		}
	}
	// A generic function or type given a lexer for a type argument works on
	// a lexer as a value of a type parameter -- saves it, restores it --
	// where nothing above sees it as a lexer.
	for id, inst := range info.Instances {
		for i := 0; i < inst.TypeArgs.Len(); i++ {
			if lexerLike(inst.TypeArgs.At(i)) {
				t.Errorf("%s: %s is instantiated with %s, a lexer as the value of a type parameter", fset.Position(id.Pos()), id.Name, inst.TypeArgs.At(i))
			}
		}
	}
	for id, obj := range info.Defs {
		if v, ok := obj.(*types.Var); ok && isLexer(v.Type()) {
			t.Errorf("%s: %s is declared a lexer value", fset.Position(id.Pos()), id.Name)
		}
		if tn, ok := obj.(*types.TypeName); ok && tn != lexerType.(*types.Named).Obj() && !tn.IsAlias() && types.Identical(tn.Type().Underlying(), lexerType.Underlying()) {
			t.Errorf("%s: %s is declared a type that is a lexer under another name", fset.Position(id.Pos()), id.Name)
		}
	}
	// local reports whether id names a variable of the function decl.
	local := func(decl *ast.FuncDecl, id *ast.Ident, name string) bool {
		obj := info.Uses[id]
		return id.Name == name && obj != nil && decl != nil && obj.Pos() >= decl.Pos() && obj.Pos() < decl.End()
	}
	forward := func(decl *ast.FuncDecl, fn types.Object, tok gotoken.Token, rhs ast.Expr) bool {
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
			return fn == back && local(decl, id, "to") || (fn == next || fn == number) && local(decl, id, "end") || fn == skipInlineImage && local(decl, id, "at")
		}
		return false
	}
	writes := 0
	for _, f := range files {
		var decl *ast.FuncDecl
		var fn types.Object
		var stack []ast.Node
		ast.Inspect(f, func(n ast.Node) bool {
			if n == nil {
				if stack[len(stack)-1] == ast.Node(decl) {
					decl, fn = nil, nil
				}
				stack = stack[:len(stack)-1]
				return true
			}
			// The node n stands in, parentheses aside.
			i, outer := len(stack)-1, n
			for i >= 0 {
				if paren, ok := stack[i].(*ast.ParenExpr); ok {
					outer, i = paren, i-1
					continue
				}
				break
			}
			var parent ast.Node
			if i >= 0 {
				parent = stack[i]
			}
			stack = append(stack, n)
			where := func() string {
				if f, ok := fn.(*types.Func); ok {
					return f.FullName()
				}
				return "the package"
			}
			switch x := n.(type) {
			case *ast.FuncDecl:
				decl, fn = x, info.Defs[x.Name]
			case *ast.AssignStmt:
				for i, lhs := range x.Lhs {
					if tv, ok := info.Types[lhs]; ok && isLexerPointer(tv.Type) {
						id, _ := lhs.(*ast.Ident)
						if x.Tok != gotoken.DEFINE || id == nil || info.Defs[id] == nil {
							t.Errorf("%s: %s assigns a lexer pointer again in %s, where it was not first made", fset.Position(x.Pos()), source(x), where())
						} else if len(x.Rhs) != len(x.Lhs) || !made(x.Rhs[i]) {
							t.Errorf("%s: %s makes a lexer variable in %s from something other than newLexer", fset.Position(x.Pos()), source(x), where())
						}
					} else if id, ok := lhs.(*ast.Ident); ok && x.Tok == gotoken.DEFINE && info.Defs[id] != nil && isLexerPointer(info.Defs[id].Type()) {
						if len(x.Rhs) != len(x.Lhs) || !made(x.Rhs[i]) {
							t.Errorf("%s: %s makes a lexer variable in %s from something other than newLexer", fset.Position(x.Pos()), source(x), where())
						}
					}
					if tv, ok := info.Types[lhs]; ok && types.Identical(tv.Type, parserType) {
						t.Errorf("%s: %s replaces a whole parser in %s", fset.Position(x.Pos()), source(x), where())
					}
					if isField(lhs, lexOf) {
						t.Errorf("%s: %s replaces a parser's lexer in %s", fset.Position(x.Pos()), source(x), where())
					}
					if !isField(lhs, pos) {
						continue
					}
					writes++
					rhs := x.Rhs[min(i, len(x.Rhs)-1)]
					if !forward(decl, fn, x.Tok, rhs) {
						t.Errorf("%s: %s sets a lexer's position in %s without back", fset.Position(x.Pos()), source(x), where())
					}
				}
			case *ast.IncDecStmt:
				if isField(x.X, pos) {
					writes++
					if x.Tok != gotoken.INC {
						t.Errorf("%s: %s steps a lexer back without back", fset.Position(x.Pos()), source(x))
					}
				}
			case *ast.UnaryExpr:
				if x.Op == gotoken.AND && isField(x.X, pos) {
					t.Errorf("%s: %s takes the address of a lexer's position", fset.Position(x.Pos()), source(x))
				}
				if x.Op == gotoken.AND && isField(x.X, lexOf) {
					t.Errorf("%s: %s takes the address of a parser's lexer", fset.Position(x.Pos()), source(x))
				}
			case *ast.ValueSpec:
				for i, name := range x.Names {
					if v := info.Defs[name]; v != nil && isLexerPointer(v.Type()) && (len(x.Values) != len(x.Names) || !made(x.Values[i])) {
						t.Errorf("%s: %s is declared a lexer variable in %s, not made from newLexer", fset.Position(name.Pos()), name.Name, where())
					}
				}
			case *ast.KeyValueExpr:
				if key, ok := x.Key.(*ast.Ident); ok && info.Uses[key] == lexOf && !made(x.Value) && !held(x.Value) {
					t.Errorf("%s: %s gives a parser a lexer in %s that newLexer did not make", fset.Position(x.Pos()), source(x), where())
				}
			case *ast.CallExpr:
				if tv, ok := info.Types[x.Fun]; ok && tv.IsType() && len(x.Args) == 1 {
					if lexerLike(tv.Type) || lexerLike(info.Types[x.Args[0]].Type) {
						t.Errorf("%s: %s converts to or from a lexer in %s", fset.Position(x.Pos()), source(x), where())
					}
				}
				if id, ok := ast.Unparen(x.Fun).(*ast.Ident); ok && len(x.Args) == 1 {
					if _, builtin := info.Uses[id].(*types.Builtin); builtin && id.Name == "new" && isLexer(info.Types[x.Args[0]].Type) && fn != construct {
						t.Errorf("%s: %s allocates a lexer in %s and not by newLexer", fset.Position(x.Pos()), source(x), where())
					}
				}
			}
			if e, ok := n.(ast.Expr); ok {
				if _, paren := n.(*ast.ParenExpr); !paren {
					tv, typed := info.Types[e]
					if typed && tv.IsValue() && isLexer(tv.Type) {
						if sel, ok := parent.(*ast.SelectorExpr); ok && sel.X == outer {
							// A field or a method of the lexer itself.
						} else if _, lit := n.(*ast.CompositeLit); lit && fn == construct {
							// The lexer newLexer builds.
						} else {
							t.Errorf("%s: %s is a lexer value in %s: a copy, or a lexer built other than by newLexer", fset.Position(n.Pos()), source(n), where())
						}
					}
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

// The tests of the build made with the pdflexprobe tag -- where what each
// lexer, with every copy of it, advances over and loads through at is
// counted from the bytes it loads and where it stands, apart from due,
// lexTrace and the sources' spelling -- run from here, in a build of their
// own, so that the ordinary test run holds the lexer to them, a short run
// included: they take a few seconds. Every file of the probe build is read
// here, so that a change to one is a change to this test's inputs and no
// result of it is taken from the test cache; every test those files declare
// must be one the run selects, and must pass by name, so that a run that
// selects nothing, or a test renamed out of it, fails. See lexprobe_test.go.
func TestTheLexerProbesHold(t *testing.T) {
	if lexProbed {
		t.Skip("this is the probe build")
	}
	const prefix = "TestLexerProbe"
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var tests []string
	fset := gotoken.NewFileSet()
	for _, name := range names {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := goparser.ParseFile(fset, name, src, goparser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		probed := false
		for _, group := range f.Comments {
			for _, c := range group.List {
				if strings.HasPrefix(c.Text, "//go:build") && strings.Contains(c.Text, "pdflexprobe") && !strings.Contains(c.Text, "!pdflexprobe") {
					probed = true
				}
			}
		}
		if !probed {
			continue
		}
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test") {
				if !strings.HasPrefix(fn.Name.Name, prefix) {
					t.Errorf("%s declares %s, which the probe build's run does not select", name, fn.Name.Name)
					continue
				}
				tests = append(tests, fn.Name.Name)
			}
		}
	}
	if len(tests) == 0 {
		t.Fatal("no file of the probe build declares a test")
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		goTool = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	cmd := exec.Command(goTool, "test", "-tags", "pdflexprobe", "-count=1", "-v", "-run", "^"+prefix, ".")
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the probe build's tests: %v\n%s", err, out)
	}
	if bytes.Contains(out, []byte("no tests to run")) {
		t.Fatalf("the probe build ran no tests:\n%s", out)
	}
	for _, name := range tests {
		if !bytes.Contains(out, []byte("--- PASS: "+name+" ")) {
			t.Errorf("the probe build did not report %s passed", name)
		}
	}
	t.Logf("%d tests of the probe build passed", len(tests))
}

// TestTheLexerProbesHold runs in every run of the ordinary build, a short one
// included: once it skipped, nothing it checks is checked. Its body is read
// here for any reference to testing.Short and any skip but the one the probe
// build itself takes, where the tests it runs are the build's own.
func TestTheLexerProbesRunInEveryRun(t *testing.T) {
	fset := gotoken.NewFileSet()
	f, err := goparser.ParseFile(fset, "lexer_steps_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var body *ast.BlockStmt
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "TestTheLexerProbesHold" {
			body = fn.Body
		}
	}
	if body == nil {
		t.Fatal("TestTheLexerProbesHold is not in lexer_steps_test.go")
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.IfStmt:
			if id, ok := x.Cond.(*ast.Ident); ok && id.Name == "lexProbed" {
				// The probe build's own skip.
				return false
			}
		case *ast.SelectorExpr:
			if pkg, ok := x.X.(*ast.Ident); ok && pkg.Name == "testing" && x.Sel.Name == "Short" {
				t.Errorf("%s: TestTheLexerProbesHold asks testing.Short", fset.Position(x.Pos()))
			}
			if strings.HasPrefix(x.Sel.Name, "Skip") {
				t.Errorf("%s: TestTheLexerProbesHold skips", fset.Position(x.Pos()))
			}
		}
		return true
	})
}
