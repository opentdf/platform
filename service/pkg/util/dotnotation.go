package util

import "strings"

// Dotnotation retrieves a value from a nested map using dot notation keys.
// Returns nil for empty keys, malformed paths (leading/trailing/double dots),
// or if the path doesn't exist in the map.
func Dotnotation(m map[string]interface{}, key string) interface{} {
	if key == "" {
		return nil
	}
	keys := strings.Split(key, ".")
	// Filter out empty segments from leading/trailing/double dots
	filtered := keys[:0]
	for _, k := range keys {
		if k != "" {
			filtered = append(filtered, k)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	for i, k := range filtered {
		if i == len(filtered)-1 {
			return m[k]
		}
		if m[k] == nil {
			return nil
		}
		var ok bool
		m, ok = m[k].(map[string]interface{})
		if !ok {
			return nil
		}
	}
	return nil
}
