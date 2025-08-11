package transformation

import (
	"fmt"
	"strings"
)

// ApplySQLTransformation applies SQL-specific transformations
func ApplySQLTransformation(value interface{}, transformation string) (interface{}, error) {
	switch transformation {
	case SQLPostgresArray:
		return ApplyPostgresArray(value)
	case SQLJSONExtract:
		return ApplyJSONExtract(value)
	case SQLDateFormat:
		return ApplyDateFormat(value)
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

// ApplyJSONExtract handles JSON extraction (placeholder for future enhancement)
func ApplyJSONExtract(value interface{}) (interface{}, error) {
	// For now, return as-is. Future enhancement could parse JSON
	// This could use encoding/json to extract specific fields
	return value, nil
}

// ApplyDateFormat handles date formatting (placeholder for future enhancement)
func ApplyDateFormat(value interface{}) (interface{}, error) {
	// For now, return as-is. Future enhancement could format dates
	// This could use time package to format dates consistently
	return value, nil
}