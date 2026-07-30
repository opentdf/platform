package transformation

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ApplySQLTransformation applies SQL-specific transformations
func ApplySQLTransformation(value interface{}, transformation string) (interface{}, error) {
	switch transformation {
	case SQLPostgresArray:
		return ApplyPostgresArray(value)
	case SQLPostgresObject:
		return ApplyPostgresObject(value)
	default:
		return nil, fmt.Errorf("unsupported SQL transformation: %s", transformation)
	}
}

// ApplyPostgresArray handles PostgreSQL array format: {item1,item2,item3}
func ApplyPostgresArray(value interface{}) (interface{}, error) {
	str, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("postgres_array transformation requires string input, got %T", value)
	}

	// Remove PostgreSQL array brackets
	str = strings.Trim(str, "{}")
	if str == "" {
		return []string{}, nil
	}

	parts := strings.Split(str, ",")
	for i, part := range parts {
		part = strings.TrimSpace(part)
		// Remove quotes if present
		part = strings.Trim(part, "\"")
		parts[i] = part
	}
	return parts, nil
}

// ApplyPostgresObject parses a PostgreSQL JSON/JSONB result into a map[string]any
// for use as a nested claim in entity resolution. Accepts string or []byte
// (as returned by the pgx driver for JSON/JSONB columns), or a map that is
// already decoded and returned as-is.
func ApplyPostgresObject(value any) (any, error) {
	if value == nil {
		return map[string]any{}, nil
	}

	var raw []byte
	switch v := value.(type) {
	case map[string]any:
		return v, nil
	case string:
		if v == "" {
			return map[string]any{}, nil
		}
		raw = []byte(v)
	case []byte:
		if len(v) == 0 {
			return map[string]any{}, nil
		}
		raw = v
	default:
		return nil, fmt.Errorf("postgres_object transformation requires string, []byte, or map input, got %T", value)
	}

	result := make(map[string]any)
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("postgres_object transformation failed to parse JSON: %w", err)
	}
	return result, nil
}
