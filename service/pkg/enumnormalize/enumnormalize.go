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
	// ParentField optionally scopes this rule to only match when JSONField
	// appears inside an object that is a direct child of a key named
	// ParentField (at any depth). This disambiguates cases where multiple
	// enum types share the same field name (e.g. "type") but live under
	// different parent keys (e.g. "contentExtractors" vs "tagProcessors").
	// When empty, the rule matches JSONField at any position (original behavior).
	ParentField string
}

// ruleLookup stores pre-built lookup tables for fast matching.
type ruleLookup struct {
	// global maps field name → prefix for rules with no ParentField.
	global map[string]string
	// scoped maps parentField → (field name → prefix) for parent-scoped rules.
	scoped map[string]map[string]string
}

// buildRuleLookup creates a ruleLookup from a set of rules.
func buildRuleLookup(rules []EnumFieldRule) ruleLookup {
	rl := ruleLookup{
		global: make(map[string]string),
		scoped: make(map[string]map[string]string),
	}
	for _, r := range rules {
		if r.ParentField == "" {
			rl.global[r.JSONField] = r.Prefix
		} else {
			if rl.scoped[r.ParentField] == nil {
				rl.scoped[r.ParentField] = make(map[string]string)
			}
			rl.scoped[r.ParentField][r.JSONField] = r.Prefix
		}
	}
	return rl
}

// normalizeJSON rewrites shorthand enum string values in body according to
// the configured rules. Values that already carry the full prefix, numeric
// values, and fields not covered by any rule pass through unchanged.
func normalizeJSON(body []byte, rl ruleLookup) ([]byte, error) {
	if len(body) == 0 || (len(rl.global) == 0 && len(rl.scoped) == 0) {
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

	normalizeValue(parsed, rl, "")

	return json.Marshal(parsed)
}

// normalizeValue recursively walks a decoded JSON value, normalizing string
// enum fields according to the lookup rules. parentKey tracks the key under
// which the current value was found, enabling parent-scoped rules.
func normalizeValue(v any, rl ruleLookup, parentKey string) {
	switch val := v.(type) {
	case map[string]any:
		for key, child := range val {
			// Check global rules (no parent scope)
			if prefix, ok := rl.global[key]; ok {
				if s, isStr := child.(string); isStr {
					val[key] = applyPrefix(s, prefix)
				}
			}
			// Check parent-scoped rules
			if scopedFields, hasParent := rl.scoped[parentKey]; hasParent {
				if scopedPrefix, hasField := scopedFields[key]; hasField {
					if s, isStr := child.(string); isStr {
						val[key] = applyPrefix(s, scopedPrefix)
					}
				}
			}
			normalizeValue(child, rl, key)
		}
	case []any:
		// Array elements inherit the parent key so that scoped rules work
		// through arrays (e.g. "contentExtractors": [{"type": "..."}]).
		for _, item := range val {
			normalizeValue(item, rl, parentKey)
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
