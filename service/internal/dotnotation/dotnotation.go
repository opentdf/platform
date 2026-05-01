package dotnotation

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// Get retrieves a value from a nested map using dot notation keys.
func Get(m map[string]any, key string) any {
	keys := strings.Split(key, ".")
	for i, k := range keys {
		if i == len(keys)-1 {
			return m[k]
		}
		if m[k] == nil {
			return nil
		}
		var ok bool
		m, ok = toMap(m[k])
		if !ok {
			return nil
		}
	}
	return nil
}

// Set stores a value in a nested map using dot notation keys, creating
// intermediate maps as needed.
func Set(m map[string]any, key string, value any) error {
	if m == nil {
		return errors.New("nil root map")
	}
	if key == "" {
		return errors.New("empty path")
	}

	keys := strings.Split(key, ".")
	for _, segment := range keys {
		if segment == "" {
			return fmt.Errorf("invalid path %q: empty segment", key)
		}
	}
	current := m
	for i, k := range keys[:len(keys)-1] {
		next, exists := current[k]
		if !exists || next == nil {
			child := map[string]any{}
			current[k] = child
			current = child
			continue
		}

		child, ok := toMap(next)
		if !ok {
			return fmt.Errorf("path collision at %s", strings.Join(keys[:i+1], "."))
		}
		current[k] = child
		current = child
	}

	current[keys[len(keys)-1]] = value
	return nil
}

func toMap(value any) (map[string]any, bool) {
	if value == nil {
		return nil, false
	}
	if typed, ok := value.(map[string]any); ok {
		return typed, true
	}

	rv := reflect.ValueOf(value)
	if rv.Kind() != reflect.Map || rv.Type().Key().Kind() != reflect.String {
		return nil, false
	}

	out := make(map[string]any, rv.Len())
	iter := rv.MapRange()
	for iter.Next() {
		out[iter.Key().String()] = iter.Value().Interface()
	}
	return out, true
}
