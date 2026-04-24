package enumnormalize

import (
	"bytes"
	"encoding/json"
	"strings"
)

// EnumFieldRule maps a JSON field name to the prefix that protobuf requires.
// When the middleware encounters a string value in a matching field that does
// not already carry the prefix, it prepends the prefix so that protojson
// recognises the canonical enum name.
type EnumFieldRule struct {
	// JSONField is the protojson camelCase field name (e.g. "operator", "booleanOperator").
	JSONField string
	// Prefix is the proto enum type prefix including trailing underscore
	// (e.g. "SUBJECT_MAPPING_OPERATOR_ENUM_").
	Prefix string
}

// fieldLookup is a pre-built map from JSON field name to enum prefix,
// constructed once at middleware initialization time.
type fieldLookup map[string]string

// buildLookup creates a fieldLookup from a set of rules. Keys are stored
// exactly as declared (protojson always emits camelCase).
func buildLookup(rules []EnumFieldRule) fieldLookup {
	m := make(fieldLookup, len(rules))
	for _, r := range rules {
		m[r.JSONField] = r.Prefix
	}
	return m
}

// normalizeJSON rewrites shorthand enum string values in body according to
// the pre-built lookup. Values that already carry the full prefix, numeric
// values, and fields not covered by any rule pass through unchanged.
func normalizeJSON(body []byte, lookup fieldLookup) ([]byte, error) {
	if len(body) == 0 || len(lookup) == 0 {
		return body, nil
	}

	// Use json.Decoder with UseNumber to preserve numeric precision
	// (avoids float64 conversion of large int64 values).
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()

	var parsed any
	if err := decoder.Decode(&parsed); err != nil {
		// Not valid JSON — pass through and let ConnectRPC surface the error.
		return body, nil //nolint:nilerr // intentional: invalid JSON is not our error to report
	}

	normalizeValue(parsed, lookup)

	return json.Marshal(parsed)
}

// normalizeValue recursively walks a decoded JSON value, normalizing string
// enum fields according to the lookup map.
func normalizeValue(v any, lookup fieldLookup) {
	switch val := v.(type) {
	case map[string]any:
		for key, child := range val {
			if prefix, ok := lookup[key]; ok {
				if s, isStr := child.(string); isStr {
					val[key] = applyPrefix(s, prefix)
				}
			}
			normalizeValue(child, lookup)
		}
	case []any:
		for _, item := range val {
			normalizeValue(item, lookup)
		}
	}
}

// applyPrefix prepends prefix to value if it is not already present
// (case-insensitive check). The value is upper-cased before comparison and
// before prepending so that "in" and "IN" both resolve correctly.
func applyPrefix(value, prefix string) string {
	upper := strings.ToUpper(value)
	if strings.HasPrefix(upper, strings.ToUpper(prefix)) {
		return upper
	}
	return prefix + upper
}
