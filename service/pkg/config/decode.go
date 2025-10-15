package config

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// secretDecodeHook converts supported inputs into Secret.
// Supported inputs:
// - string -> literal secret
// - map[string]any -> reference, e.g., {"fromEnv":"OPENTDF_FOO"}
func secretDecodeHook(from, to reflect.Type, data any) (any, error) {
	// Only target Secret type
	if to != reflect.TypeOf(Secret{}) {
		return data, nil
	}

	//nolint:exhaustive // reflect.Kind has many variants; we only handle string and map inputs here
	switch from.Kind() {
	case reflect.String:
		// Support friendly inline directives: "env:VAR", "file:/path", "literal:..."
		s := reflect.ValueOf(data).String()
		switch {
		case strings.HasPrefix(s, "env:"):
			v := strings.TrimPrefix(s, "env:")
			if v == "" {
				return nil, errors.New("empty env directive")
			}
			return NewEnvSecret(v), nil
		case strings.HasPrefix(s, "file:"):
			v := strings.TrimPrefix(s, "file:")
			if v == "" {
				return nil, errors.New("empty file directive")
			}
			return NewFileSecret(v), nil
		case strings.HasPrefix(s, "literal:"):
			return NewLiteralSecret(strings.TrimPrefix(s, "literal:")), nil
		default:
			// Default to literal
			return NewLiteralSecret(s), nil
		}
	case reflect.Map:
		// Must be map[string]any (case-insensitive key handling)
		m, okm := data.(map[string]any)
		if !okm {
			return nil, fmt.Errorf("invalid secret map type: %T", data)
		}
		// Normalize keys to lowercase for robust matching (Viper may lowercase keys)
		lower := make(map[string]any, len(m))
		for k, v := range m {
			lower[strings.ToLower(k)] = v
		}
		if env, ok := lower["fromenv"].(string); ok && env != "" {
			return NewEnvSecret(env), nil
		}
		if file, ok2 := lower["fromfile"].(string); ok2 && file != "" {
			return NewFileSecret(file), nil
		}
		// Future: support {"fromURI":"aws-secretsmanager://..."}
		return nil, errors.New("unsupported secret map, expected {fromEnv:string} or {fromFile:string}")
	default:
		return nil, fmt.Errorf("cannot decode %s into Secret", from.Kind())
	}
}
