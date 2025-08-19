package transformation

import (
	"fmt"
)

// Registry provides a unified interface for applying transformations
// across all provider types with fallback to common transformations
type Registry struct{}

// NewRegistry creates a new transformation registry
func NewRegistry() *Registry {
	return &Registry{}
}

// ApplyTransformation applies a transformation with provider-aware fallback
func (r *Registry) ApplyTransformation(value interface{}, transformation string, providerType string) (interface{}, error) {
	if transformation == "" {
		return value, nil
	}

	// Try provider-specific transformations first
	switch providerType {
	case "sql":
		if result, err := r.tryApplySQL(value, transformation); err == nil {
			return result, nil
		}
	case "ldap":
		if result, err := r.tryApplyLDAP(value, transformation); err == nil {
			return result, nil
		}
	case "claims":
		if result, err := r.tryApplyClaims(value, transformation); err == nil {
			return result, nil
		}
	}

	// Fallback to common transformations
	if IsCommonTransformation(transformation) {
		return ApplyCommonTransformation(value, transformation)
	}

	return nil, fmt.Errorf("unsupported transformation '%s' for provider type '%s'", transformation, providerType)
}

// GetSupportedTransformations returns all transformations supported by a provider type
func (r *Registry) GetSupportedTransformations(providerType string) []string {
	switch providerType {
	case "sql":
		return GetAllSQLTransformations()
	case "ldap":
		return GetAllLDAPTransformations()
	case "claims":
		return GetAllClaimsTransformations()
	default:
		return GetCommonTransformations()
	}
}

// ValidateTransformation checks if a transformation is supported by a provider type
func (r *Registry) ValidateTransformation(transformation string, providerType string) error {
	if !IsSupportedByProvider(transformation, providerType) {
		return fmt.Errorf("transformation '%s' is not supported by provider type '%s'", transformation, providerType)
	}
	return nil
}

// tryApplySQL attempts to apply SQL-specific transformations
func (r *Registry) tryApplySQL(value interface{}, transformation string) (interface{}, error) {
	// Check if it's an SQL-specific transformation
	sqlTransformations := GetSQLTransformations()
	for _, t := range sqlTransformations {
		if t == transformation {
			return ApplySQLTransformation(value, transformation)
		}
	}
	return nil, fmt.Errorf("not an SQL transformation: %s", transformation)
}

// tryApplyLDAP attempts to apply LDAP-specific transformations
func (r *Registry) tryApplyLDAP(value interface{}, transformation string) (interface{}, error) {
	// Check if it's an LDAP-specific transformation
	ldapTransformations := GetLDAPTransformations()
	for _, t := range ldapTransformations {
		if t == transformation {
			return ApplyLDAPTransformation(value, transformation)
		}
	}
	return nil, fmt.Errorf("not an LDAP transformation: %s", transformation)
}

// tryApplyClaims attempts to apply Claims-specific transformations
func (r *Registry) tryApplyClaims(value interface{}, transformation string) (interface{}, error) {
	// Check if it's a Claims-specific transformation
	claimsTransformations := GetClaimsTransformations()
	for _, t := range claimsTransformations {
		if t == transformation {
			return ApplyClaimsTransformation(value, transformation)
		}
	}
	return nil, fmt.Errorf("not a Claims transformation: %s", transformation)
}

// Global registry instance for convenience
var DefaultRegistry = NewRegistry()
