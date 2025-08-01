package claims

import (
	"fmt"
	"strings"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
)

// ClaimsMapper handles mapping for JWT Claims providers
type ClaimsMapper struct {
	providerType string
}

// Ensure ClaimsMapper implements types.Mapper interface
var _ types.Mapper = (*ClaimsMapper)(nil)

// NewClaimsMapper creates a new Claims mapper
func NewClaimsMapper() *ClaimsMapper {
	return &ClaimsMapper{
		providerType: "claims",
	}
}

// ExtractParameters extracts parameters for Claims provider (minimal since it uses JWT directly)
func (m *ClaimsMapper) ExtractParameters(jwtClaims types.JWTClaims, inputMapping []types.InputMapping) (map[string]interface{}, error) {
	// Claims provider doesn't typically need input mapping since it uses JWT claims directly
	// But we support it for consistency and potential filtering use cases
	params := make(map[string]interface{})

	for _, mapping := range inputMapping {
		claimValue, exists := jwtClaims[mapping.JWTClaim]
		if !exists {
			if mapping.Required {
				return nil, fmt.Errorf("required JWT claim '%s' not found", mapping.JWTClaim)
			}
			continue
		}

		params[mapping.Parameter] = claimValue
	}

	return params, nil
}

// TransformResults transforms JWT claims to standardized claims
func (m *ClaimsMapper) TransformResults(rawData map[string]interface{}, outputMapping []types.OutputMapping) (map[string]interface{}, error) {
	claims := make(map[string]interface{})

	for _, mapping := range outputMapping {
		// Check if source claim exists in raw data (JWT claims)
		value, exists := rawData[mapping.SourceClaim]
		if !exists {
			// Skip missing claims unless required
			continue
		}

		// Apply transformation if specified
		transformedValue, err := m.ApplyTransformation(value, mapping.Transformation)
		if err != nil {
			return nil, fmt.Errorf("transformation failed for claim %s: %w", mapping.SourceClaim, err)
		}

		claims[mapping.ClaimName] = transformedValue
	}

	return claims, nil
}

// ValidateInputMapping validates Claims-specific input mapping requirements
func (m *ClaimsMapper) ValidateInputMapping(inputMapping []types.InputMapping) error {
	// Base validation
	for _, mapping := range inputMapping {
		if mapping.JWTClaim == "" {
			return fmt.Errorf("jwt_claim cannot be empty")
		}
		if mapping.Parameter == "" {
			return fmt.Errorf("parameter cannot be empty")
		}
	}

	// Claims provider has minimal input mapping requirements
	// since it primarily uses JWT claims directly
	return nil
}

// ValidateOutputMapping validates Claims-specific output mapping requirements
func (m *ClaimsMapper) ValidateOutputMapping(outputMapping []types.OutputMapping) error {
	// Base validation
	for _, mapping := range outputMapping {
		if mapping.ClaimName == "" {
			return fmt.Errorf("claim_name cannot be empty")
		}
	}

	for _, mapping := range outputMapping {
		if mapping.SourceClaim == "" {
			return fmt.Errorf("source_claim cannot be empty for Claims mapper")
		}

		// Validate transformation is supported
		if mapping.Transformation != "" && !m.isTransformationSupported(mapping.Transformation) {
			return fmt.Errorf("unsupported transformation for Claims mapper: %s", mapping.Transformation)
		}
	}

	return nil
}

// GetSupportedTransformations returns Claims-specific transformations
func (m *ClaimsMapper) GetSupportedTransformations() []string {
	return []string{
		// Common transformations
		"csv_to_array",
		"array",
		"string",
		"lowercase",
		"uppercase",
		// Claims-specific transformations
		"jwt_decode_base64",
		"jwt_parse_json",
		"jwt_extract_scope",
		"jwt_normalize_groups",
	}
}

// ApplyTransformation applies Claims-specific transformations
func (m *ClaimsMapper) ApplyTransformation(value interface{}, transformation string) (interface{}, error) {
	if transformation == "" {
		return value, nil
	}

	// Apply common transformations first
	switch transformation {
	case "csv_to_array":
		if str, ok := value.(string); ok {
			if str == "" {
				return []string{}, nil
			}
			parts := strings.Split(str, ",")
			for i, part := range parts {
				parts[i] = strings.TrimSpace(part)
			}
			return parts, nil
		}
		return nil, fmt.Errorf("csv_to_array transformation requires string input, got %T", value)

	case "array":
		// Ensure value is an array
		if arr, ok := value.([]interface{}); ok {
			return arr, nil
		}
		if arr, ok := value.([]string); ok {
			result := make([]interface{}, len(arr))
			for i, v := range arr {
				result[i] = v
			}
			return result, nil
		}
		return []interface{}{value}, nil

	case "string":
		return fmt.Sprintf("%v", value), nil

	case "lowercase":
		if str, ok := value.(string); ok {
			return strings.ToLower(str), nil
		}
		return strings.ToLower(fmt.Sprintf("%v", value)), nil

	case "uppercase":
		if str, ok := value.(string); ok {
			return strings.ToUpper(str), nil
		}
		return strings.ToUpper(fmt.Sprintf("%v", value)), nil

	// Apply Claims-specific transformations
	case "jwt_decode_base64":
		// Decode base64 encoded claim values
		if str, ok := value.(string); ok {
			// For now, return as-is. Future enhancement could decode base64
			return str, nil
		}
		return nil, fmt.Errorf("jwt_decode_base64 transformation requires string input, got %T", value)

	case "jwt_parse_json":
		// Parse JSON string claim values
		if str, ok := value.(string); ok {
			// For now, return as-is. Future enhancement could parse JSON
			return str, nil
		}
		return nil, fmt.Errorf("jwt_parse_json transformation requires string input, got %T", value)

	case "jwt_extract_scope":
		// Extract scopes from space-separated scope claim
		if str, ok := value.(string); ok {
			if str == "" {
				return []string{}, nil
			}
			scopes := strings.Fields(str) // Split on whitespace
			return scopes, nil
		}
		return nil, fmt.Errorf("jwt_extract_scope transformation requires string input, got %T", value)

	case "jwt_normalize_groups":
		// Normalize group names from various formats
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
		if arr, ok := value.([]interface{}); ok {
			result := make([]string, len(arr))
			for i, v := range arr {
				result[i] = fmt.Sprintf("%v", v)
			}
			return result, nil
		}
		if arr, ok := value.([]string); ok {
			return arr, nil
		}
		return nil, fmt.Errorf("jwt_normalize_groups transformation requires string or array input, got %T", value)

	default:
		return nil, fmt.Errorf("unsupported Claims transformation: %s", transformation)
	}
}

// isTransformationSupported checks if a transformation is supported by Claims mapper
func (m *ClaimsMapper) isTransformationSupported(transformation string) bool {
	supported := m.GetSupportedTransformations()
	for _, t := range supported {
		if t == transformation {
			return true
		}
	}
	return false
}