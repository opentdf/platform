package config

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/service/logger"
	serviceconfig "github.com/opentdf/platform/service/pkg/config"
	"github.com/stretchr/testify/require"
)

func Test_GetSharedPolicyConfig_MaxObjectCountsDecode(t *testing.T) {
	t.Parallel()

	cfg, err := GetSharedPolicyConfig(serviceconfig.ServiceConfig{
		"max_object_counts": map[string]any{
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

func Test_EnforceObjectLimit_AtLimit_Fails(t *testing.T) {
	t.Parallel()

	err := EnforceObjectLimit(ObjectTypeAttributeDefinitionsPerNamespace, 10, 10, 1)
	require.ErrorIs(t, err, ErrObjectLimitExceeded)

	var logs bytes.Buffer
	testLogger := &logger.Logger{Logger: slog.New(slog.NewJSONHandler(&logs, nil))}
	connectErr := ObjectLimitConnectError(t.Context(), testLogger, "create", err)
	require.Error(t, connectErr)
	require.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(connectErr))
	require.Contains(t, connectErr.Error(), "maximum 10")

	var entry map[string]any
	require.NoError(t, json.Unmarshal(logs.Bytes(), &entry))
	require.Equal(t, "policy object limit reached; rejected mutation", entry["msg"])
	require.Equal(t, "create", entry["operation"])
	require.Equal(t, "attribute definitions per namespace", entry["object_type"])
	require.EqualValues(t, 10, entry["current_count"])
	require.EqualValues(t, 10, entry["configured_maximum"])
	require.EqualValues(t, 1, entry["attempted_addition"])
	require.Equal(t, false, entry["configured_maximum_below_current_count"])
}

func Test_ObjectLimitConnectError_LimitBelowCurrentCount_LogsWhenMutationRejected(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	testLogger := &logger.Logger{Logger: slog.New(slog.NewJSONHandler(&logs, nil))}
	err := EnforceObjectLimit(ObjectTypeAttributeDefinitionsPerNamespace, 4, 5, 1)

	require.Error(t, ObjectLimitConnectError(t.Context(), testLogger, "update", err))

	var entry map[string]any
	require.NoError(t, json.Unmarshal(logs.Bytes(), &entry))
	require.Equal(t, "policy object limit reached; rejected mutation", entry["msg"])
	require.Equal(t, "update", entry["operation"])
	require.EqualValues(t, 5, entry["current_count"])
	require.EqualValues(t, 4, entry["configured_maximum"])
	require.Equal(t, true, entry["configured_maximum_below_current_count"])
}

func Test_EnforceObjectLimit_ZeroLimit_Succeeds(t *testing.T) {
	t.Parallel()

	require.NoError(t, EnforceObjectLimit(ObjectTypeAttributeDefinitionsPerNamespace, 0, 100, 1))
}
