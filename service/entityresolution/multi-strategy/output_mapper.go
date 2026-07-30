package multistrategy

import (
	"errors"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/transformation"
	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
)

var ErrFieldNotFound = errors.New("field not found in raw result")

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

	// Resolve provider type for transformation dispatch. Providers stamp
	// this in RawResult.Metadata; empty string is safe and falls back to
	// common transformations only.
	providerType, _ := rawResult.Metadata["provider_type"].(string)

	// Apply output mappings
	for _, mapping := range outputMappings {
		if err := om.applyMapping(rawResult, entityResult, mapping, providerType); err != nil {
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
func (om *OutputMapper) applyMapping(rawResult *types.RawResult, entityResult *types.EntityResult, mapping types.OutputMapping, providerType string) error {
	// Get source value based on provider type
	sourceValue, err := om.getSourceValue(rawResult, mapping)
	if err != nil {
		// Skip mapping if field not found
		if errors.Is(err, ErrFieldNotFound) {
			return nil
		}
		return err
	}

	// Skip if no source value found
	if sourceValue == nil {
		return nil
	}

	// Apply transformation via the shared registry so all provider-specific
	// and common transformations stay in one place.
	transformedValue, err := transformation.DefaultRegistry.ApplyTransformation(sourceValue, mapping.Transformation, providerType)
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
		// Field not found - return sentinel error that caller can handle
		return nil, ErrFieldNotFound
	}

	return value, nil
}
