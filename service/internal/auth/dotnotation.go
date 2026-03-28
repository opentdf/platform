package auth

import "strings"

// DotNotation retrieves a value from a nested map using dot notation keys.
func DotNotation(m map[string]any, key string) any {
	keys := strings.Split(key, ".")
	for i, k := range keys {
		if i == len(keys)-1 {
			return m[k]
		}
		if m[k] == nil {
			return nil
		}
		var ok bool
		m, ok = m[k].(map[string]any)
		if !ok {
			return nil
		}
	}
	return nil
}
