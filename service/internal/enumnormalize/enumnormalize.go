package enumnormalize

import (
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

// NormalizeJSON rewrites shorthand enum string values in body according to
// rules. Values that already carry the full prefix, numeric values, and fields
// not covered by any rule pass through unchanged.
func NormalizeJSON(body []byte, rules []EnumFieldRule) ([]byte, error) {
	if len(body) == 0 || len(rules) == 0 {
		return body, nil
	}

	// Build a lookup: lowercase field name → prefix
	lookup := make(map[string]string, len(rules))
	for _, r := range rules {
		lookup[strings.ToLower(r.JSONField)] = r.Prefix
	}

	var parsed any
	if err := json.Unmarshal(body, &parsed); err != nil {
		// Not valid JSON — pass through and let ConnectRPC surface the error.
		return body, nil //nolint:nilerr // intentional: invalid JSON is not our error to report
	}

	normalizeValue(parsed, lookup)

	return json.Marshal(parsed)
}

// normalizeValue recursively walks a decoded JSON value, normalizing string
// enum fields according to the lookup map.
func normalizeValue(v any, lookup map[string]string) {
	switch val := v.(type) {
	case map[string]any:
		for key, child := range val {
			if prefix, ok := lookup[strings.ToLower(key)]; ok {
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
