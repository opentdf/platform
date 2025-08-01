package sql

import (
	"fmt"
	"strings"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
)

// SQLMapper handles mapping for SQL providers
type SQLMapper struct {
	providerType string
}

// Ensure SQLMapper implements types.Mapper interface
var _ types.Mapper = (*SQLMapper)(nil)

// NewSQLMapper creates a new SQL mapper
func NewSQLMapper() *SQLMapper {
	return &SQLMapper{
		providerType: "sql",
	}
}

// ExtractParameters extracts parameters for SQL queries with proper validation
func (m *SQLMapper) ExtractParameters(jwtClaims types.JWTClaims, inputMapping []types.InputMapping) (map[string]interface{}, error) {
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

	// SQL-specific parameter validation and sanitization
	for paramName, paramValue := range params {
		// Ensure no SQL injection attempts in parameter names
		if strings.ContainsAny(paramName, ";'\"\\") {
			return nil, fmt.Errorf("invalid parameter name contains SQL metacharacters: %s", paramName)
		}

		// Convert parameter values to appropriate SQL types
		params[paramName] = m.sanitizeParameterValue(paramValue)
	}

	return params, nil
}

// TransformResults transforms SQL query results to standardized claims
func (m *SQLMapper) TransformResults(rawData map[string]interface{}, outputMapping []types.OutputMapping) (map[string]interface{}, error) {
	claims := make(map[string]interface{})

	for _, mapping := range outputMapping {
		// Check if source column exists in raw data
		value, exists := rawData[mapping.SourceColumn]
		if !exists {
			// Skip missing columns unless required
			continue
		}

		// Apply transformation if specified
		transformedValue, err := m.ApplyTransformation(value, mapping.Transformation)
		if err != nil {
			return nil, fmt.Errorf("transformation failed for column %s: %w", mapping.SourceColumn, err)
		}

		claims[mapping.ClaimName] = transformedValue
	}

	return claims, nil
}

// ValidateInputMapping validates SQL-specific input mapping requirements
func (m *SQLMapper) ValidateInputMapping(inputMapping []types.InputMapping) error {
	// Base validation
	for _, mapping := range inputMapping {
		if mapping.JWTClaim == "" {
			return fmt.Errorf("jwt_claim cannot be empty")
		}
		if mapping.Parameter == "" {
			return fmt.Errorf("parameter cannot be empty")
		}
	}

	for _, mapping := range inputMapping {
		// SQL parameter names must be valid identifiers
		if !isValidSQLIdentifier(mapping.Parameter) {
			return fmt.Errorf("invalid SQL parameter name: %s", mapping.Parameter)
		}
	}

	return nil
}

// ValidateOutputMapping validates SQL-specific output mapping requirements
func (m *SQLMapper) ValidateOutputMapping(outputMapping []types.OutputMapping) error {
	// Base validation
	for _, mapping := range outputMapping {
		if mapping.ClaimName == "" {
			return fmt.Errorf("claim_name cannot be empty")
		}
	}

	for _, mapping := range outputMapping {
		if mapping.SourceColumn == "" {
			return fmt.Errorf("source_column cannot be empty for SQL mapper")
		}

		// Validate column name is a valid SQL identifier
		if !isValidSQLIdentifier(mapping.SourceColumn) {
			return fmt.Errorf("invalid SQL column name: %s", mapping.SourceColumn)
		}

		// Validate transformation is supported
		if mapping.Transformation != "" && !m.isTransformationSupported(mapping.Transformation) {
			return fmt.Errorf("unsupported transformation for SQL mapper: %s", mapping.Transformation)
		}
	}

	return nil
}

// GetSupportedTransformations returns SQL-specific transformations
func (m *SQLMapper) GetSupportedTransformations() []string {
	return []string{
		// Common transformations
		"csv_to_array",
		"array",
		"string",
		"lowercase",
		"uppercase",
		// SQL-specific transformations
		"postgres_array",
		"json_extract",
		"date_format",
	}
}

// ApplyTransformation applies SQL-specific transformations
func (m *SQLMapper) ApplyTransformation(value interface{}, transformation string) (interface{}, error) {
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

	// Apply SQL-specific transformations
	case "postgres_array":
		// Handle PostgreSQL array format: {item1,item2,item3}
		if str, ok := value.(string); ok {
			str = strings.Trim(str, "{}")
			if str == "" {
				return []string{}, nil
			}
			parts := strings.Split(str, ",")
			for i, part := range parts {
				parts[i] = strings.TrimSpace(part)
				// Remove quotes if present
				parts[i] = strings.Trim(parts[i], "\"")
			}
			return parts, nil
		}
		return nil, fmt.Errorf("postgres_array transformation requires string input, got %T", value)

	case "json_extract":
		// For now, return as-is. Future enhancement could parse JSON
		return value, nil

	case "date_format":
		// For now, return as-is. Future enhancement could format dates
		return value, nil

	default:
		return nil, fmt.Errorf("unsupported SQL transformation: %s", transformation)
	}
}

// sanitizeParameterValue ensures parameter values are safe for SQL queries
func (m *SQLMapper) sanitizeParameterValue(value interface{}) interface{} {
	// The actual SQL driver will handle parameterization, but we can do basic cleanup
	if str, ok := value.(string); ok {
		// Trim whitespace
		return strings.TrimSpace(str)
	}
	return value
}

// isValidSQLIdentifier checks if a string is a valid SQL identifier
func isValidSQLIdentifier(name string) bool {
	if name == "" {
		return false
	}

	// Must start with letter or underscore
	if !((name[0] >= 'a' && name[0] <= 'z') || (name[0] >= 'A' && name[0] <= 'Z') || name[0] == '_') {
		return false
	}

	// Rest must be letters, digits, or underscores
	for i := 1; i < len(name); i++ {
		char := name[i]
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_') {
			return false
		}
	}

	return true
}

// isTransformationSupported checks if a transformation is supported by SQL mapper
func (m *SQLMapper) isTransformationSupported(transformation string) bool {
	supported := m.GetSupportedTransformations()
	for _, t := range supported {
		if t == transformation {
			return true
		}
	}
	return false
}