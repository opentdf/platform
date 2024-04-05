package jqbuiltin

import (
	"bytes"
	"encoding/json"
	"log/slog"

	"github.com/itchyny/gojq"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
)

func JQBuiltin() {
	rego.RegisterBuiltin2(&rego.Function{
		Name:             "jq.evaluate",
		Decl:             types.NewFunction(types.Args(types.A, types.S), types.A),
		Memoize:          true,
		Nondeterministic: true,
	}, func(ctx rego.BuiltinContext, a, b *ast.Term) (*ast.Term, error) {
		slog.Debug("JQ plugin invoked")
		var input map[string]any
		var query string

		if err := ast.As(a.Value, &input); err != nil {
			return nil, err
		} else if err := ast.As(b.Value, &query); err != nil {
			return nil, err
		}

		res, err := ExecuteQuery(input, query)
		if err != nil {
			return nil, err
		}
		respBytes, err := json.Marshal(res)
		if err != nil {
			return nil, err
		}
		reader := bytes.NewReader(respBytes)
		v, err := ast.ValueFromReader(reader)
		if err != nil {
			return nil, err
		}

		return ast.NewTerm(v), nil
	},
	)
}

func ExecuteQuery(inputJson map[string]any, queryString string) ([]any, error) {
	query, err := gojq.Parse(queryString)
	if err != nil {
		return nil, err
	}
	iter := query.Run(inputJson)
	found := []any{}
	for {
		v, ok := iter.Next()
		if !ok {
			break
		}
		slog.Info("v: ", v)
		if err, ok := v.(error); ok {
			if err, ok := err.(*gojq.HaltError); ok && err.Value() == nil {
				break
			}
			// ignore error: we don't have a match but that is not an error state in this case
		} else {
			if v != nil {
				found = append(found, v)
			}
		}
	}

	return found, nil

}
