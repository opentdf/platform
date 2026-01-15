package ldap

import (
	"errors"
	"fmt"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/transformation"
	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
)

// Mapper handles mapping for LDAP providers
type Mapper struct {
	providerType string
}

// Ensure Mapper implements types.Mapper interface
var _ types.Mapper = (*Mapper)(nil)

// NewMapper creates a new LDAP mapper
func NewMapper() *Mapper {
	return &Mapper{
		providerType: "ldap",
	}
}

// ExtractParameters extracts parameters for LDAP queries with proper validation
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

	// LDAP-specific parameter validation and sanitization
	for paramName, paramValue := range params {
		// Escape LDAP filter metacharacters in parameter values
		if str, ok := paramValue.(string); ok {
			params[paramName] = m.escapeLDAPFilter(str)
		}
	}

	return params, nil
}

// TransformResults transforms LDAP search results to standardized claims
func (m *Mapper) TransformResults(rawData map[string]interface{}, outputMapping []types.OutputMapping) (map[string]interface{}, error) {
	claims := make(map[string]interface{})

	for _, mapping := range outputMapping {
		// Check if source attribute exists in raw data
		value, exists := rawData[mapping.SourceAttribute]
		if !exists {
			// Skip missing attributes unless required
			continue
		}

		// Apply transformation if specified
		transformedValue, err := m.ApplyTransformation(value, mapping.Transformation)
		if err != nil {
			return nil, fmt.Errorf("transformation failed for attribute %s: %w", mapping.SourceAttribute, err)
		}

		claims[mapping.ClaimName] = transformedValue
	}

	return claims, nil
}

// ValidateInputMapping validates LDAP-specific input mapping requirements
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
		// LDAP parameter names should be valid template variables
		if !isValidTemplateVariable(mapping.Parameter) {
			return fmt.Errorf("invalid LDAP template parameter name: %s", mapping.Parameter)
		}
	}

	return nil
}

// ValidateOutputMapping validates LDAP-specific output mapping requirements
func (m *Mapper) ValidateOutputMapping(outputMapping []types.OutputMapping) error {
	// Base validation
	for _, mapping := range outputMapping {
		if mapping.ClaimName == "" {
			return errors.New("claim_name cannot be empty")
		}
	}

	for _, mapping := range outputMapping {
		if mapping.SourceAttribute == "" {
			return errors.New("source_attribute cannot be empty for LDAP mapper")
		}

		// Validate attribute name is a valid LDAP attribute
		if !isValidLDAPAttribute(mapping.SourceAttribute) {
			return fmt.Errorf("invalid LDAP attribute name: %s", mapping.SourceAttribute)
		}

		// Validate transformation is supported
		if mapping.Transformation != "" && !m.isTransformationSupported(mapping.Transformation) {
			return fmt.Errorf("unsupported transformation for LDAP mapper: %s", mapping.Transformation)
		}
	}

	return nil
}

// GetSupportedTransformations returns LDAP-specific transformations
func (m *Mapper) GetSupportedTransformations() []string {
	return transformation.GetAllLDAPTransformations()
}

// ApplyTransformation applies LDAP-specific transformations
func (m *Mapper) ApplyTransformation(value interface{}, transformationName string) (interface{}, error) {
	return transformation.DefaultRegistry.ApplyTransformation(value, transformationName, "ldap")
}

// escapeLDAPFilter escapes special characters in LDAP filter values
func (m *Mapper) escapeLDAPFilter(value string) string {
	return transformation.EscapeLDAPFilter(value)
}

// isValidTemplateVariable checks if a string is a valid template variable name
func isValidTemplateVariable(name string) bool {
	if name == "" {
		return false
	}

	// Must start with letter or underscore
	//nolint:staticcheck // QF1001: De Morgan's law would make this less readable
	if !((name[0] >= 'a' && name[0] <= 'z') || (name[0] >= 'A' && name[0] <= 'Z') || name[0] == '_') {
		return false
	}

	// Rest must be letters, digits, or underscores
	for i := 1; i < len(name); i++ {
		char := name[i]
		//nolint:staticcheck // QF1001: De Morgan's law would make this less readable
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_') {
			return false
		}
	}

	return true
}

// isValidLDAPAttribute checks if a string is a valid LDAP attribute name
func isValidLDAPAttribute(name string) bool {
	if name == "" {
		return false
	}

	// LDAP attribute names can contain letters, digits, and hyphens
	// Must start with a letter
	//nolint:staticcheck // QF1001: De Morgan's law would make this less readable
	if !((name[0] >= 'a' && name[0] <= 'z') || (name[0] >= 'A' && name[0] <= 'Z')) {
		return false
	}

	for i := 1; i < len(name); i++ {
		char := name[i]
		//nolint:staticcheck // QF1001: De Morgan's law would make this less readable
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-') {
			return false
		}
	}

	return true
}

// isTransformationSupported checks if a transformation is supported by LDAP mapper
func (m *Mapper) isTransformationSupported(transformationName string) bool {
	return transformation.IsSupportedByProvider(transformationName, "ldap")
}
