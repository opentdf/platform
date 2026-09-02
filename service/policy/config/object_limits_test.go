package config

import (
	"testing"

	serviceconfig "github.com/opentdf/platform/service/pkg/config"
	"github.com/stretchr/testify/require"
)

func Test_GetSharedPolicyConfig_MaxObjectCountsDecode(t *testing.T) {
	t.Parallel()

	cfg, err := GetSharedPolicyConfig(serviceconfig.ServiceConfig{
		"max_object_counts": map[string]any{
			"namespaces":                              11,
			"attribute_definitions_per_namespace":     1,
			"attribute_values_per_definition":         2,
			"resource_mapping_groups_per_namespace":   3,
			"resource_mappings_per_attribute_value":   4,
			"subject_mappings_per_attribute_value":    5,
			"subject_condition_sets_per_namespace":    6,
			"obligation_definitions_per_namespace":    7,
			"obligation_values_per_definition":        8,
			"obligation_triggers_per_attribute_value": 9,
			"actions_per_namespace":                   10,
		},
	})
	require.NoError(t, err)
	require.Equal(t, MaxObjectCounts{
		Namespaces:                          11,
		AttributeDefinitionsPerNamespace:    1,
		AttributeValuesPerDefinition:        2,
		ResourceMappingGroupsPerNamespace:   3,
		ResourceMappingsPerAttributeValue:   4,
		SubjectMappingsPerAttributeValue:    5,
		SubjectConditionSetsPerNamespace:    6,
		ObligationDefinitionsPerNamespace:   7,
		ObligationValuesPerDefinition:       8,
		ObligationTriggersPerAttributeValue: 9,
		ActionsPerNamespace:                 10,
	}, cfg.MaxObjectCounts)
}

func Test_MaxObjectCounts_ValidateNegativeLimit_Fails(t *testing.T) {
	t.Parallel()

	err := (MaxObjectCounts{AttributeDefinitionsPerNamespace: -1}).Validate()
	require.EqualError(t, err, "policy object limit [attribute_definitions_per_namespace] must be zero or positive")
}

func Test_EnforceObjectLimit_ZeroLimit_Succeeds(t *testing.T) {
	t.Parallel()

	require.NoError(t, EnforceObjectLimit(ObjectTypeAttributeDefinitionsPerNamespace, 0, 100, 1))
}
