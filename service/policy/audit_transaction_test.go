package policy_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Audit outcomes must be recorded after RunInTx reports the commit outcome.
func TestAuditOutsideTransactionCallbacks(t *testing.T) {
	fset := token.NewFileSet()
	transactions := 0
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			method, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || method.Sel.Name != "RunInTx" {
				return true
			}
			transactions++
			for _, arg := range call.Args {
				callback, isCallback := arg.(*ast.FuncLit)
				if !isCallback {
					continue
				}
				ast.Inspect(callback.Body, func(child ast.Node) bool {
					selector, isSelector := child.(*ast.SelectorExpr)
					if isSelector && selector.Sel.Name == "Audit" {
						t.Errorf("audit inside transaction callback at %s", fset.Position(selector.Pos()))
					}
					return true
				})
			}
			return true
		})
		return nil
	})
	require.NoError(t, err)
	require.Positive(t, transactions)
}
