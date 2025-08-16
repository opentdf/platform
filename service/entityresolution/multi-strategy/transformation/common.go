package transformation

import (
	"fmt"
	"strings"
)

// ApplyCommonTransformation applies common transformations that work across all providers
func ApplyCommonTransformation(value interface{}, transformation string) (interface{}, error) {
	switch transformation {
	case CommonCSVToArray:
		return ApplyCSVToArray(value)
	case CommonArray:
		return ApplyArray(value)
	case CommonString:
		return ApplyString(value)
	case CommonLowercase:
		return ApplyLowercase(value)
	case CommonUppercase:
		return ApplyUppercase(value)
	default:
		return nil, fmt.Errorf("unsupported common transformation: %s", transformation)
	}
}

// ApplyCSVToArray converts comma-separated strings to string arrays
func ApplyCSVToArray(value interface{}) (interface{}, error) {
	str, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("csv_to_array transformation requires string input, got %T", value)
	}

	if str == "" {
		return []string{}, nil
	}

	parts := strings.Split(str, ",")
	for i, part := range parts {
		parts[i] = strings.TrimSpace(part)
	}
	return parts, nil
}

// ApplyArray ensures the value is returned as an array type
func ApplyArray(value interface{}) (interface{}, error) {
	// Already an []interface{}
	if arr, ok := value.([]interface{}); ok {
		return arr, nil
	}

	// Convert []string to []interface{}
	if arr, ok := value.([]string); ok {
		result := make([]interface{}, len(arr))
		for i, v := range arr {
			result[i] = v
		}
		return result, nil
	}

	// Wrap single value in array
	return []interface{}{value}, nil
}

// ApplyString converts any value to its string representation
func ApplyString(value interface{}) (interface{}, error) {
	return fmt.Sprintf("%v", value), nil
}

// ApplyLowercase converts string values to lowercase
func ApplyLowercase(value interface{}) (interface{}, error) {
	if str, ok := value.(string); ok {
		return strings.ToLower(str), nil
	}
	return strings.ToLower(fmt.Sprintf("%v", value)), nil
}

// ApplyUppercase converts string values to uppercase
func ApplyUppercase(value interface{}) (interface{}, error) {
	if str, ok := value.(string); ok {
		return strings.ToUpper(str), nil
	}
	return strings.ToUpper(fmt.Sprintf("%v", value)), nil
}
