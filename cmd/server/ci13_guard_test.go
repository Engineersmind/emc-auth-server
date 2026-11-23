package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The [CI-13] allowlist in scripts/govulncheck-gate.sh lets GO-2026-6872 and
// GO-2026-6875 through because echo v4 has no fix and govulncheck cannot tell
// whether we reach the vulnerable code. That is safe only while the conditions
// below hold. scripts/govulncheck-gate.sh runs these tests whenever it allows an
// ID, so an allowlisted ID blocks again if any of them breaks.
//
// why: without this, the allowlist matched on OSV ID alone; registering echo's
// RateLimiter or Proxy middleware, or dropping IPExtractor, would expose us while
// CI stayed green (review on PR #215).

const echoMiddlewarePath = "github.com/labstack/echo/v4/middleware"

// Echo middleware the two advisories need: 6872 is the RateLimiter keyed on
// RealIP(), 6875 is the Proxy middleware forwarding the client's X-Real-IP.
var ci13ForbiddenEchoMiddleware = map[string]bool{
	"RateLimiter":                         true,
	"RateLimiterWithConfig":               true,
	"RateLimiterConfig":                   true,
	"DefaultRateLimiterConfig":            true,
	"NewRateLimiterMemoryStore":           true,
	"NewRateLimiterMemoryStoreWithConfig": true,
	"Proxy":                               true,
	"ProxyWithConfig":                     true,
	"ProxyConfig":                         true,
	"DefaultProxyConfig":                  true,
	"NewRandomBalancer":                   true,
	"NewRoundRobinBalancer":               true,
}

type ci13File struct {
	rel  string
	fset *token.FileSet
	file *ast.File
}

// ci13NonTestFiles parses every non-test .go file in the module.
func ci13NonTestFiles(t *testing.T) []ci13File {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root not found at %s: %v", root, err)
	}

	var files []ci13File
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		files = append(files, ci13File{rel: filepath.ToSlash(rel), fset: fset, file: f})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no Go files found; the walk is broken")
	}
	return files
}

// importName returns the name a file uses for importPath, or "" if it does not
// import it.
func importName(f *ast.File, importPath string) string {
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != importPath {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name
		}
		// A major-version suffix is not the package name: .../echo/v4 is echo.
		parts := strings.Split(importPath, "/")
		last := parts[len(parts)-1]
		if len(parts) > 1 && len(last) > 1 && last[0] == 'v' && strings.Trim(last[1:], "0123456789") == "" {
			return parts[len(parts)-2]
		}
		return last
	}
	return ""
}

func TestCI13NoEchoRateLimiterOrProxy(t *testing.T) {
	for _, f := range ci13NonTestFiles(t) {
		name := importName(f.file, echoMiddlewarePath)
		switch name {
		case "", "_":
			continue
		case ".":
			t.Errorf("%s dot-imports %s; CI-13 cannot check which middleware it uses", f.rel, echoMiddlewarePath)
			continue
		}
		ast.Inspect(f.file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == name && ci13ForbiddenEchoMiddleware[sel.Sel.Name] {
				t.Errorf("%s: uses echo middleware.%s. GO-2026-6872/6875 are allowlisted only because "+
					"we use neither echo's RateLimiter nor its Proxy; use internal/api/middleware instead, "+
					"or remove the ID from the CI-13 allowlist", f.fset.Position(sel.Pos()), sel.Sel.Name)
			}
			return true
		})
	}
}

func TestCI13SingleEchoWithClientIPExtractor(t *testing.T) {
	var echoNews []string
	for _, f := range ci13NonTestFiles(t) {
		name := importName(f.file, "github.com/labstack/echo/v4")
		if name == "" || name == "_" {
			continue
		}
		ast.Inspect(f.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "New" {
				if x, ok := sel.X.(*ast.Ident); ok && x.Name == name {
					echoNews = append(echoNews, f.fset.Position(call.Pos()).String())
				}
			}
			return true
		})
	}
	// A second Echo instance would need its own IPExtractor; extend this test
	// for it before adding one.
	if len(echoNews) != 1 || !strings.Contains(filepath.ToSlash(echoNews[0]), "cmd/server/main.go") {
		t.Fatalf("want exactly one echo.New(), in cmd/server/main.go; found %d: %v", len(echoNews), echoNews)
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	set := false
	ast.Inspect(f, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		lhs, ok := as.Lhs[0].(*ast.SelectorExpr)
		if !ok || lhs.Sel.Name != "IPExtractor" {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok {
			t.Errorf("%s: IPExtractor is not set from middleware.ClientIPExtractor", fset.Position(as.Pos()))
			return true
		}
		if fn, ok := call.Fun.(*ast.SelectorExpr); ok && fn.Sel.Name == "ClientIPExtractor" {
			set = true
		} else {
			t.Errorf("%s: IPExtractor is not set from middleware.ClientIPExtractor", fset.Position(as.Pos()))
		}
		return true
	})
	if !set {
		t.Fatal("cmd/server/main.go must set e.IPExtractor = middleware.ClientIPExtractor(...); " +
			"GO-2026-6872/6875 are allowlisted only because Echo#IPExtractor is not nil")
	}
}
