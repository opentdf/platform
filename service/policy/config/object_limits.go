package config

import (
	"errors"
	"fmt"

	"connectrpc.com/connect"
)

const (
	ObjectTypeAttributeDefinitions          = "attribute definitions"
	ObjectTypeAttributeValuesPerDefinition  = "attribute values per definition"
	ObjectTypeResourceMappingGroups         = "resource mapping groups"
	ObjectTypeResourceMappings              = "resource mappings"
	ObjectTypeSubjectMappings               = "subject mappings"
	ObjectTypeSubjectConditionSets          = "subject condition sets"
	ObjectTypeObligationDefinitions         = "obligation definitions"
	ObjectTypeObligationValuesPerDefinition = "obligation values per definition"
	ObjectTypeObligationTriggers            = "obligation triggers"
)

// ErrObjectLimitExceeded identifies a create rejected by a configured object limit.
var ErrObjectLimitExceeded = errors.New("policy object limit exceeded")

// ObjectLimits configures per-namespace policy object limits. Zero disables an
// individual limit so existing OpenTDF deployments remain unlimited by default.
type ObjectLimits struct {
	AttributeDefinitions          int64 `mapstructure:"attribute_definitions" default:"0"`
	AttributeValuesPerDefinition  int64 `mapstructure:"attribute_values_per_definition" default:"0"`
	ResourceMappingGroups         int64 `mapstructure:"resource_mapping_groups" default:"0"`
	ResourceMappings              int64 `mapstructure:"resource_mappings" default:"0"`
	SubjectMappings               int64 `mapstructure:"subject_mappings" default:"0"`
	SubjectConditionSets          int64 `mapstructure:"subject_condition_sets" default:"0"`
	ObligationDefinitions         int64 `mapstructure:"obligation_definitions" default:"0"`
	ObligationValuesPerDefinition int64 `mapstructure:"obligation_values_per_definition" default:"0"`
	ObligationTriggers            int64 `mapstructure:"obligation_triggers" default:"0"`
}

func (l ObjectLimits) Validate() error {
	limits := map[string]int64{
		"attribute_definitions":            l.AttributeDefinitions,
		"attribute_values_per_definition":  l.AttributeValuesPerDefinition,
		"resource_mapping_groups":          l.ResourceMappingGroups,
		"resource_mappings":                l.ResourceMappings,
		"subject_mappings":                 l.SubjectMappings,
		"subject_condition_sets":           l.SubjectConditionSets,
		"obligation_definitions":           l.ObligationDefinitions,
		"obligation_values_per_definition": l.ObligationValuesPerDefinition,
		"obligation_triggers":              l.ObligationTriggers,
	}
	for name, limit := range limits {
		if limit < 0 {
			return fmt.Errorf("policy object limit [%s] must be zero or positive", name)
		}
	}
	return nil
}

// ObjectLimitError describes which configured object limit rejected a create.
type ObjectLimitError struct {
	ObjectType string
	Limit      int64
}

func (e *ObjectLimitError) Error() string {
	return fmt.Sprintf("policy object limit reached for %s (maximum %d); contact your administrator to request a higher limit", e.ObjectType, e.Limit)
}

func (e *ObjectLimitError) Unwrap() error {
	return ErrObjectLimitExceeded
}

// EnforceObjectLimit rejects an addition that would exceed a nonzero limit.
func EnforceObjectLimit(objectType string, limit, current int64, added int) error {
	if limit == 0 || added == 0 {
		return nil
	}
	if current+int64(added) > limit {
		return &ObjectLimitError{ObjectType: objectType, Limit: limit}
	}
	return nil
}

// ObjectLimitConnectError translates a configured limit error for the public
// service boundary while leaving unrelated errors to the service's normal path.
func ObjectLimitConnectError(err error) error {
	if !errors.Is(err, ErrObjectLimitExceeded) {
		return nil
	}
	return connect.NewError(connect.CodeResourceExhausted, err)
}
