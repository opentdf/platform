package jqbuiltin

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strconv"

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
	}, func(_ rego.BuiltinContext, a, b *ast.Term) (*ast.Term, error) {
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

func ExecuteQuery(inputJSON map[string]any, queryString string) ([]any, error) {
	// first unescape the query string
	unescapedQueryString, err := unescapeQueryString(queryString)
	if err != nil {
		return nil, err
	}

	query, err := gojq.Parse(unescapedQueryString)
	if err != nil {
		return nil, err
	}
	iter := query.Run(inputJSON)
	found := []any{}
	for {
		v, ok := iter.Next()
		if !ok {
			break
		}
		if err, ok2 := v.(error); ok2 {
			//nolint:errorlint // temp following gojq example
			if err, ok3 := err.(*gojq.HaltError); ok3 && err.Value() == nil {
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

// unescape any strings within the provided string
func unescapeQueryString(queryString string) (string, error) {
	if queryString == "" {
		return "", nil
	}
	unquotedQueryString, err := strconv.Unquote(queryString)
	if err != nil {
		if err.Error() == "invalid syntax" {
			slog.Debug("invalid syntax error when unquoting means there was nothing to unescape. carry on.", slog.String("queryString", queryString))
			unquotedQueryString = queryString
		} else {
			slog.Error("failed to unescape double quotes in subject external selector value", slog.String("queryString", queryString), slog.String("error", err.Error()))
			return "", err
		}
	}
	slog.Debug("unescaped any double quotes in jq query string", slog.String("queryString", unquotedQueryString))
	return unquotedQueryString, nil
}
