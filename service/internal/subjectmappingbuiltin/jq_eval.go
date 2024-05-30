package subjectmappingbuiltin

import (
	"log/slog"
	"strconv"

	"github.com/itchyny/gojq"
)

func ExecuteQuery(inputJSON map[string]any, queryString string) ([]any, error) {
	slog.Debug("Executing query", "query=", queryString)
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
