package multistrategy

import "reflect"

// isEmptyValue reports whether a source value should be replaced by a configured
// default: nil, "", or a zero-length slice/array/map. Notably 0, false and " " are
// not empty.
func isEmptyValue(value interface{}) bool {
	if value == nil {
		return true
	}

	rv := reflect.ValueOf(value)
	switch rv.Kind() { //nolint:exhaustive // only container-ish kinds can be empty
	case reflect.String, reflect.Slice, reflect.Array, reflect.Map:
		return rv.Len() == 0
	case reflect.Ptr, reflect.Interface:
		return rv.IsNil()
	default:
		return false
	}
}

// cloneValue deep-copies maps and slices. Output mappings are shared across
// concurrent requests, so a default must never be aliased into an entity result.
func cloneValue(value interface{}) interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(typed))
		for key, item := range typed {
			out[key] = cloneValue(item)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(typed))
		for i, item := range typed {
			out[i] = cloneValue(item)
		}
		return out
	default:
		return value
	}
}

// sanitizeClaimValue strips nulls from a claim value, returning false when the whole
// value drops out. lib/flattening errors on any null, which fails the entire subject
// mapping evaluation for the entity. Empty maps and slices are kept: they flatten
// safely and the postgres_object contract depends on them.
func sanitizeClaimValue(value interface{}) (interface{}, bool) {
	if value == nil {
		return nil, false
	}

	switch typed := value.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(typed))
		for key, item := range typed {
			if sanitized, ok := sanitizeClaimValue(item); ok {
				out[key] = sanitized
			}
		}
		return out, true
	case []interface{}:
		out := make([]interface{}, 0, len(typed))
		for _, item := range typed {
			if sanitized, ok := sanitizeClaimValue(item); ok {
				out = append(out, sanitized)
			}
		}
		return out, true
	}

	// Typed nils reach flattening as null; nil containers become empty ones
	rv := reflect.ValueOf(value)
	if rv.Kind() == reflect.Map && rv.IsNil() {
		return map[string]interface{}{}, true
	}
	switch rv.Kind() { //nolint:exhaustive // only nilable kinds are relevant
	case reflect.Slice:
		if rv.IsNil() {
			return []interface{}{}, true
		}
	case reflect.Ptr, reflect.Interface, reflect.Func, reflect.Chan:
		if rv.IsNil() {
			return nil, false
		}
	}

	return value, true
}
