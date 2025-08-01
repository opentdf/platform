package ldap

import (
	"fmt"
	"strings"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
)

// LDAPMapper handles mapping for LDAP providers
type LDAPMapper struct {
	providerType string
}

// Ensure LDAPMapper implements types.Mapper interface
var _ types.Mapper = (*LDAPMapper)(nil)

// NewLDAPMapper creates a new LDAP mapper
func NewLDAPMapper() *LDAPMapper {
	return &LDAPMapper{
		providerType: "ldap",
	}
}

// ExtractParameters extracts parameters for LDAP queries with proper validation
func (m *LDAPMapper) ExtractParameters(jwtClaims types.JWTClaims, inputMapping []types.InputMapping) (map[string]interface{}, error) {
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
func (m *LDAPMapper) TransformResults(rawData map[string]interface{}, outputMapping []types.OutputMapping) (map[string]interface{}, error) {
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
func (m *LDAPMapper) ValidateInputMapping(inputMapping []types.InputMapping) error {
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
		// LDAP parameter names should be valid template variables
		if !isValidTemplateVariable(mapping.Parameter) {
			return fmt.Errorf("invalid LDAP template parameter name: %s", mapping.Parameter)
		}
	}

	return nil
}

// ValidateOutputMapping validates LDAP-specific output mapping requirements
func (m *LDAPMapper) ValidateOutputMapping(outputMapping []types.OutputMapping) error {
	// Base validation
	for _, mapping := range outputMapping {
		if mapping.ClaimName == "" {
			return fmt.Errorf("claim_name cannot be empty")
		}
	}

	for _, mapping := range outputMapping {
		if mapping.SourceAttribute == "" {
			return fmt.Errorf("source_attribute cannot be empty for LDAP mapper")
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
func (m *LDAPMapper) GetSupportedTransformations() []string {
	return []string{
		// Common transformations
		"csv_to_array",
		"array",
		"string",
		"lowercase",
		"uppercase",
		// LDAP-specific transformations
		"ldap_dn_to_cn_array",
		"ldap_dn_to_cn",
		"ldap_attribute_values",
		"ad_group_name",
	}
}

// ApplyTransformation applies LDAP-specific transformations
func (m *LDAPMapper) ApplyTransformation(value interface{}, transformation string) (interface{}, error) {
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

	// Apply LDAP-specific transformations
	case "ldap_dn_to_cn_array":
		// Convert array of DNs to array of CNs
		if arr, ok := value.([]interface{}); ok {
			result := make([]string, 0, len(arr))
			for _, item := range arr {
				if str, ok := item.(string); ok {
					cn := m.extractCNFromDN(str)
					if cn != "" {
						result = append(result, cn)
					}
				}
			}
			return result, nil
		}
		if arr, ok := value.([]string); ok {
			result := make([]string, 0, len(arr))
			for _, dn := range arr {
				cn := m.extractCNFromDN(dn)
				if cn != "" {
					result = append(result, cn)
				}
			}
			return result, nil
		}
		return nil, fmt.Errorf("ldap_dn_to_cn_array transformation requires array input, got %T", value)

	case "ldap_dn_to_cn":
		// Convert single DN to CN
		if str, ok := value.(string); ok {
			return m.extractCNFromDN(str), nil
		}
		return nil, fmt.Errorf("ldap_dn_to_cn transformation requires string input, got %T", value)

	case "ldap_attribute_values":
		// Extract values from LDAP attribute (handle multi-valued attributes)
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
		// Single value
		return []string{fmt.Sprintf("%v", value)}, nil

	case "ad_group_name":
		// Extract group name from Active Directory group DN
		if str, ok := value.(string); ok {
			// Handle both DN format and simple group names
			if strings.Contains(str, "CN=") {
				return m.extractCNFromDN(str), nil
			}
			return str, nil
		}
		return nil, fmt.Errorf("ad_group_name transformation requires string input, got %T", value)

	default:
		return nil, fmt.Errorf("unsupported LDAP transformation: %s", transformation)
	}
}

// escapeLDAPFilter escapes special characters in LDAP filter values
func (m *LDAPMapper) escapeLDAPFilter(value string) string {
	// LDAP filter metacharacters that need escaping
	replacer := strings.NewReplacer(
		"\\", "\\5c",
		"*", "\\2a",
		"(", "\\28",
		")", "\\29",
		"\x00", "\\00",
	)
	return replacer.Replace(value)
}

// extractCNFromDN extracts the Common Name (CN) from a Distinguished Name (DN)
func (m *LDAPMapper) extractCNFromDN(dn string) string {
	// Simple CN extraction from DN like "CN=Users,OU=Groups,DC=example,DC=com"
	parts := strings.Split(dn, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "CN=") {
			return part[3:] // Remove "CN=" prefix
		}
	}
	return ""
}

// isValidTemplateVariable checks if a string is a valid template variable name
func isValidTemplateVariable(name string) bool {
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

// isValidLDAPAttribute checks if a string is a valid LDAP attribute name
func isValidLDAPAttribute(name string) bool {
	if name == "" {
		return false
	}

	// LDAP attribute names can contain letters, digits, and hyphens
	// Must start with a letter
	if !((name[0] >= 'a' && name[0] <= 'z') || (name[0] >= 'A' && name[0] <= 'Z')) {
		return false
	}

	for i := 1; i < len(name); i++ {
		char := name[i]
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-') {
			return false
		}
	}

	return true
}

// isTransformationSupported checks if a transformation is supported by LDAP mapper
func (m *LDAPMapper) isTransformationSupported(transformation string) bool {
	supported := m.GetSupportedTransformations()
	for _, t := range supported {
		if t == transformation {
			return true
		}
	}
	return false
}