package multistrategy

import (
	"errors"
	"fmt"
	"strings"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
)

// Names of the value transformations shared by the mappers in this package.
const (
	transformationCSVToArray = "csv_to_array"
	transformationArray      = "array"
	transformationString     = "string"
	transformationLowercase  = "lowercase"
	transformationUppercase  = "uppercase"
)

// BaseMapper provides common functionality for all mapper implementations
type BaseMapper struct {
	providerType string
}

// NewBaseMapper creates a new base mapper
func NewBaseMapper(providerType string) *BaseMapper {
	return &BaseMapper{
		providerType: providerType,
	}
}

// ExtractParameters provides default implementation for parameter extraction
func (m *BaseMapper) ExtractParameters(jwtClaims types.JWTClaims, inputMapping []types.InputMapping) (map[string]interface{}, error) {
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

// ValidateInputMapping provides default validation for input mapping
func (m *BaseMapper) ValidateInputMapping(inputMapping []types.InputMapping) error {
	for _, mapping := range inputMapping {
		if mapping.JWTClaim == "" {
			return errors.New("jwt_claim cannot be empty")
		}
		if mapping.Parameter == "" {
			return errors.New("parameter cannot be empty")
		}
	}
	return nil
}

// ValidateOutputMapping provides default validation for output mapping
func (m *BaseMapper) ValidateOutputMapping(outputMapping []types.OutputMapping) error {
	for _, mapping := range outputMapping {
		if mapping.ClaimName == "" {
			return errors.New("claim_name cannot be empty")
		}
		// Source field validation is provider-specific
	}
	return nil
}

// ApplyTransformation applies standard transformations to values
func (m *BaseMapper) ApplyTransformation(value interface{}, transformation string) (interface{}, error) {
	if transformation == "" {
		return value, nil
	}

	switch transformation {
	case transformationCSVToArray:
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

	case transformationArray:
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

	case transformationString:
		return fmt.Sprintf("%v", value), nil

	case transformationLowercase:
		if str, ok := value.(string); ok {
			return strings.ToLower(str), nil
		}
		return strings.ToLower(fmt.Sprintf("%v", value)), nil

	case transformationUppercase:
		if str, ok := value.(string); ok {
			return strings.ToUpper(str), nil
		}
		return strings.ToUpper(fmt.Sprintf("%v", value)), nil

	default:
		return nil, fmt.Errorf("unsupported transformation: %s", transformation)
	}
}

// GetCommonTransformations returns transformations supported by all mappers
func (m *BaseMapper) GetCommonTransformations() []string {
	return []string{
		transformationCSVToArray,
		transformationArray,
		transformationString,
		transformationLowercase,
		transformationUppercase,
	}
}
