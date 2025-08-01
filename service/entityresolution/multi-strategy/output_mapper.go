package multistrategy

import (
	"fmt"
	"strings"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
)

// OutputMapper handles transformation of raw provider results to final entity claims
type OutputMapper struct{}

// NewOutputMapper creates a new output mapper
func NewOutputMapper() *OutputMapper {
	return &OutputMapper{}
}

// MapResult transforms raw provider result to final entity result using output mapping rules
func (om *OutputMapper) MapResult(rawResult *types.RawResult, outputMappings []types.OutputMapping, originalID string) (*types.EntityResult, error) {
	if rawResult == nil {
		return nil, types.NewMappingError("raw result is nil", map[string]interface{}{
			"original_id": originalID,
		})
	}

	// Create entity result
	entityResult := &types.EntityResult{
		OriginalID: originalID,
		Claims:     make(map[string]interface{}),
		Metadata:   make(map[string]interface{}),
	}

	// Copy metadata from raw result
	for key, value := range rawResult.Metadata {
		entityResult.Metadata[key] = value
	}

	// Apply output mappings
	for _, mapping := range outputMappings {
		if err := om.applyMapping(rawResult, entityResult, mapping); err != nil {
			return nil, types.WrapMultiStrategyError(
				types.ErrorTypeMapping,
				"failed to apply output mapping",
				err,
				map[string]interface{}{
					"original_id": originalID,
					"claim_name":  mapping.ClaimName,
					"mapping":     mapping,
				},
			)
		}
	}

	// Add mapping metadata
	entityResult.Metadata["output_mappings_applied"] = len(outputMappings)
	entityResult.Metadata["claims_mapped"] = len(entityResult.Claims)

	return entityResult, nil
}

// applyMapping applies a single output mapping rule
func (om *OutputMapper) applyMapping(rawResult *types.RawResult, entityResult *types.EntityResult, mapping types.OutputMapping) error {
	// Get source value based on provider type
	sourceValue, err := om.getSourceValue(rawResult, mapping)
	if err != nil {
		return err
	}

	// Skip if no source value found
	if sourceValue == nil {
		return nil
	}

	// Apply transformation if specified
	transformedValue, err := om.applyTransformation(sourceValue, mapping.Transformation)
	if err != nil {
		return types.WrapMultiStrategyError(
			types.ErrorTypeMapping,
			"transformation failed",
			err,
			map[string]interface{}{
				"claim_name":     mapping.ClaimName,
				"transformation": mapping.Transformation,
				"source_value":   sourceValue,
			},
		)
	}

	// Set the claim value
	entityResult.Claims[mapping.ClaimName] = transformedValue

	return nil
}

// getSourceValue extracts the source value from raw result based on mapping configuration
func (om *OutputMapper) getSourceValue(rawResult *types.RawResult, mapping types.OutputMapping) (interface{}, error) {
	// Determine source field based on mapping configuration
	var sourceField string

	switch {
	case mapping.SourceColumn != "":
		sourceField = mapping.SourceColumn // SQL column
	case mapping.SourceAttribute != "":
		sourceField = mapping.SourceAttribute // LDAP attribute
	case mapping.SourceClaim != "":
		sourceField = mapping.SourceClaim // JWT claim
	case mapping.SourceKey != "":
		sourceField = mapping.SourceKey // Redis key
	default:
		return nil, types.NewMappingError("no source field specified in mapping", map[string]interface{}{
			"claim_name": mapping.ClaimName,
			"mapping":    mapping,
		})
	}

	// Get value from raw result data
	value, exists := rawResult.Data[sourceField]
	if !exists {
		// Field not found - this is not necessarily an error
		return nil, nil
	}

	return value, nil
}

// applyTransformation applies the specified transformation to the source value
func (om *OutputMapper) applyTransformation(value interface{}, transformation string) (interface{}, error) {
	if transformation == "" {
		return value, nil
	}

	switch strings.ToLower(transformation) {
	case "array":
		return om.transformToArray(value)

	case "csv_to_array":
		return om.transformCSVToArray(value)

	case "ldap_dn_to_cn_array":
		return om.transformLDAPDNToCNArray(value)

	case "lowercase":
		return om.transformToLowercase(value)

	case "uppercase":
		return om.transformToUppercase(value)

	case "trim":
		return om.transformTrim(value)

	default:
		return nil, fmt.Errorf("unknown transformation: %s", transformation)
	}
}

// transformToArray ensures the value is an array
func (om *OutputMapper) transformToArray(value interface{}) (interface{}, error) {
	if value == nil {
		return []interface{}{}, nil
	}

	// If already an array, return as-is
	if arr, ok := value.([]interface{}); ok {
		return arr, nil
	}

	// If string array, convert to interface array
	if strArr, ok := value.([]string); ok {
		result := make([]interface{}, len(strArr))
		for i, s := range strArr {
			result[i] = s
		}
		return result, nil
	}

	// Otherwise, wrap single value in array
	return []interface{}{value}, nil
}

// transformCSVToArray splits a CSV string into an array
func (om *OutputMapper) transformCSVToArray(value interface{}) (interface{}, error) {
	if value == nil {
		return []interface{}{}, nil
	}

	// Convert to string
	str, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("csv_to_array transformation requires string input, got %T", value)
	}

	// Split by comma and trim whitespace
	parts := strings.Split(str, ",")
	result := make([]interface{}, 0, len(parts))

	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}

	return result, nil
}

// transformLDAPDNToCNArray extracts CN values from LDAP DN strings
func (om *OutputMapper) transformLDAPDNToCNArray(value interface{}) (interface{}, error) {
	if value == nil {
		return []interface{}{}, nil
	}

	// Handle array of DNs
	if arr, ok := value.([]interface{}); ok {
		result := make([]interface{}, 0)
		for _, item := range arr {
			if itemStr, itemOk := item.(string); itemOk {
				cn := om.extractCNFromDN(itemStr)
				if cn != "" {
					result = append(result, cn)
				}
			}
		}
		return result, nil
	}

	// Handle string array
	if strArr, ok := value.([]string); ok {
		result := make([]interface{}, 0)
		for _, str := range strArr {
			cn := om.extractCNFromDN(str)
			if cn != "" {
				result = append(result, cn)
			}
		}
		return result, nil
	}

	// Handle single DN string
	if str, ok := value.(string); ok {
		cn := om.extractCNFromDN(str)
		if cn != "" {
			return []interface{}{cn}, nil
		}
		return []interface{}{}, nil
	}

	return nil, fmt.Errorf("ldap_dn_to_cn_array transformation requires string or array input, got %T", value)
}

// transformToLowercase converts string values to lowercase
func (om *OutputMapper) transformToLowercase(value interface{}) (interface{}, error) {
	if value == nil {
		return nil, nil
	}

	if str, ok := value.(string); ok {
		return strings.ToLower(str), nil
	}

	return nil, fmt.Errorf("lowercase transformation requires string input, got %T", value)
}

// transformToUppercase converts string values to uppercase
func (om *OutputMapper) transformToUppercase(value interface{}) (interface{}, error) {
	if value == nil {
		return nil, nil
	}

	if str, ok := value.(string); ok {
		return strings.ToUpper(str), nil
	}

	return nil, fmt.Errorf("uppercase transformation requires string input, got %T", value)
}

// transformTrim trims whitespace from string values
func (om *OutputMapper) transformTrim(value interface{}) (interface{}, error) {
	if value == nil {
		return nil, nil
	}

	if str, ok := value.(string); ok {
		return strings.TrimSpace(str), nil
	}

	return nil, fmt.Errorf("trim transformation requires string input, got %T", value)
}

// extractCNFromDN extracts the CN (Common Name) component from an LDAP DN
func (om *OutputMapper) extractCNFromDN(dn string) string {
	// Simple CN extraction - looks for CN= at the beginning or after comma
	dn = strings.TrimSpace(dn)
	if dn == "" {
		return ""
	}

	// Split DN into components
	components := strings.Split(dn, ",")

	for _, component := range components {
		component = strings.TrimSpace(component)
		if strings.HasPrefix(strings.ToUpper(component), "CN=") {
			return strings.TrimSpace(component[3:])
		}
	}

	return ""
}
