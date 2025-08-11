package transformation

import (
	"fmt"
	"strings"
)

// ApplyClaimsTransformation applies Claims-specific transformations
func ApplyClaimsTransformation(value interface{}, transformation string) (interface{}, error) {
	switch transformation {
	case ClaimsDecodeBase64:
		return ApplyJWTDecodeBase64(value)
	case ClaimsParseJSON:
		return ApplyJWTParseJSON(value)
	case ClaimsExtractScope:
		return ApplyJWTExtractScope(value)
	case ClaimsNormalizeGroups:
		return ApplyJWTNormalizeGroups(value)
	default:
		return nil, fmt.Errorf("unsupported Claims transformation: %s", transformation)
	}
}

// ApplyJWTDecodeBase64 decodes base64 encoded claim values
func ApplyJWTDecodeBase64(value interface{}) (interface{}, error) {
	str, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("jwt_decode_base64 transformation requires string input, got %T", value)
	}

	// For now, return as-is. Future enhancement could decode base64
	// This would use encoding/base64 package:
	// decoded, err := base64.StdEncoding.DecodeString(str)
	// return string(decoded), err
	return str, nil
}

// ApplyJWTParseJSON parses JSON string claim values
func ApplyJWTParseJSON(value interface{}) (interface{}, error) {
	str, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("jwt_parse_json transformation requires string input, got %T", value)
	}

	// For now, return as-is. Future enhancement could parse JSON
	// This would use encoding/json package:
	// var result interface{}
	// err := json.Unmarshal([]byte(str), &result)
	// return result, err
	return str, nil
}

// ApplyJWTExtractScope extracts scopes from space-separated scope claim
// OAuth2/OIDC scopes are typically space-separated per RFC 6749
func ApplyJWTExtractScope(value interface{}) (interface{}, error) {
	str, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("jwt_extract_scope transformation requires string input, got %T", value)
	}

	if str == "" {
		return []string{}, nil
	}

	// Split on whitespace (space, tab, newline, etc.)
	scopes := strings.Fields(str)
	return scopes, nil
}

// ApplyJWTNormalizeGroups normalizes group names from various formats
// Handles comma-separated, space-separated, or array formats
func ApplyJWTNormalizeGroups(value interface{}) (interface{}, error) {
	// Handle string inputs
	if str, ok := value.(string); ok {
		// Handle comma-separated groups
		if strings.Contains(str, ",") {
			parts := strings.Split(str, ",")
			result := make([]string, len(parts))
			for i, part := range parts {
				result[i] = strings.TrimSpace(part)
			}
			return result, nil
		}

		// Handle space-separated groups
		if strings.Contains(str, " ") {
			return strings.Fields(str), nil
		}

		// Single group
		return []string{str}, nil
	}

	// Handle []interface{} arrays
	if arr, ok := value.([]interface{}); ok {
		result := make([]string, len(arr))
		for i, v := range arr {
			result[i] = fmt.Sprintf("%v", v)
		}
		return result, nil
	}

	// Handle []string arrays (already normalized)
	if arr, ok := value.([]string); ok {
		return arr, nil
	}

	return nil, fmt.Errorf("jwt_normalize_groups transformation requires string or array input, got %T", value)
}