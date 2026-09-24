package multistrategy

import (
	"reflect"
	"strings"
)

// lookupSourceField resolves a source field against raw provider data. An exact flat
// key wins over dot-path traversal, keeping literal keys with dots working. Dotted
// paths traverse decoded maps only, since sources resolve before transformations.
func lookupSourceField(data map[string]interface{}, field string) (interface{}, bool) {
	if value, exists := data[field]; exists {
		return value, true
	}
	if !strings.Contains(field, ".") {
		return nil, false
	}

	segments := strings.Split(field, ".")
	current := data
	for _, segment := range segments[:len(segments)-1] {
		next, exists := current[segment]
		if !exists {
			return nil, false
		}
		child, ok := asStringKeyedMap(next)
		if !ok {
			return nil, false
		}
		current = child
	}

	value, exists := current[segments[len(segments)-1]]
	return value, exists
}

// asStringKeyedMap coerces any string-keyed map to map[string]interface{}.
func asStringKeyedMap(value interface{}) (map[string]interface{}, bool) {
	if value == nil {
		return nil, false
	}
	if typed, ok := value.(map[string]interface{}); ok {
		return typed, true
	}

	rv := reflect.ValueOf(value)
	if rv.Kind() != reflect.Map || rv.Type().Key().Kind() != reflect.String {
		return nil, false
	}

	out := make(map[string]interface{}, rv.Len())
	iter := rv.MapRange()
	for iter.Next() {
		out[iter.Key().String()] = iter.Value().Interface()
	}
	return out, true
}
