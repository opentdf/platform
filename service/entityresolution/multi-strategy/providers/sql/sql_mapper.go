package sql

import (
	"errors"
	"fmt"
	"strings"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/transformation"
	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
)

// Mapper handles mapping for SQL providers
type Mapper struct {
	providerType string
}

// Ensure Mapper implements types.Mapper interface
var _ types.Mapper = (*Mapper)(nil)

// NewMapper creates a new SQL mapper
func NewMapper() *Mapper {
	return &Mapper{
		providerType: "sql",
	}
}

// ExtractParameters extracts parameters for SQL queries with proper validation
func (m *Mapper) ExtractParameters(jwtClaims types.JWTClaims, inputMapping []types.InputMapping) (map[string]interface{}, error) {
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
func (m *Mapper) TransformResults(rawData map[string]interface{}, outputMapping []types.OutputMapping) (map[string]interface{}, error) {
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
func (m *Mapper) ValidateInputMapping(inputMapping []types.InputMapping) error {
	// Base validation
	for _, mapping := range inputMapping {
		if mapping.JWTClaim == "" {
			return errors.New("jwt_claim cannot be empty")
		}
		if mapping.Parameter == "" {
			return errors.New("parameter cannot be empty")
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
func (m *Mapper) ValidateOutputMapping(outputMapping []types.OutputMapping) error {
	// Base validation
	for _, mapping := range outputMapping {
		if mapping.ClaimName == "" {
			return errors.New("claim_name cannot be empty")
		}
	}

	for _, mapping := range outputMapping {
		if mapping.SourceColumn == "" {
			return errors.New("source_column cannot be empty for SQL mapper")
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
func (m *Mapper) GetSupportedTransformations() []string {
	return transformation.GetAllSQLTransformations()
}

// ApplyTransformation applies SQL-specific transformations
func (m *Mapper) ApplyTransformation(value interface{}, transformationName string) (interface{}, error) {
	return transformation.DefaultRegistry.ApplyTransformation(value, transformationName, "sql")
}

// sanitizeParameterValue ensures parameter values are safe for SQL queries
func (m *Mapper) sanitizeParameterValue(value interface{}) interface{} {
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
func (m *Mapper) isTransformationSupported(transformationName string) bool {
	return transformation.IsSupportedByProvider(transformationName, "sql")
}
