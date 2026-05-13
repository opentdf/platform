package auth

import internaldotnotation "github.com/opentdf/platform/service/internal/dotnotation"

// DotNotation retrieves a value from a nested map using dot notation keys.
func DotNotation(m map[string]any, key string) any {
	return internaldotnotation.Get(m, key)
}
