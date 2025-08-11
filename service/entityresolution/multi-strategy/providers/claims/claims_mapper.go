package claims

import (
	"fmt"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/transformation"
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
	return transformation.GetAllClaimsTransformations()
}

// ApplyTransformation applies Claims-specific transformations
func (m *ClaimsMapper) ApplyTransformation(value interface{}, transformationName string) (interface{}, error) {
	return transformation.DefaultRegistry.ApplyTransformation(value, transformationName, "claims")
}

// isTransformationSupported checks if a transformation is supported by Claims mapper
func (m *ClaimsMapper) isTransformationSupported(transformationName string) bool {
	return transformation.IsSupportedByProvider(transformationName, "claims")
}