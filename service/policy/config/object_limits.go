package config

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/service/logger"
)

const (
	ObjectTypeNamespaces                          = "namespaces"
	ObjectTypeAttributeDefinitionsPerNamespace    = "attribute definitions per namespace"
	ObjectTypeAttributeValuesPerDefinition        = "attribute values per definition"
	ObjectTypeResourceMappingGroupsPerNamespace   = "resource mapping groups per namespace"
	ObjectTypeResourceMappingsPerAttributeValue   = "resource mappings per attribute value"
	ObjectTypeSubjectMappingsPerAttributeValue    = "subject mappings per attribute value"
	ObjectTypeSubjectConditionSetsPerNamespace    = "subject condition sets per namespace"
	ObjectTypeObligationDefinitionsPerNamespace   = "obligation definitions per namespace"
	ObjectTypeObligationValuesPerDefinition       = "obligation values per definition"
	ObjectTypeObligationTriggersPerAttributeValue = "obligation triggers per attribute value"
	ObjectTypeActionsPerNamespace                 = "actions per namespace"
)

// ErrObjectLimitExceeded identifies a create rejected by a configured object limit.
var ErrObjectLimitExceeded = errors.New("policy object limit exceeded")

// MaxObjectCounts configures maximum policy object counts. Zero disables an
// individual maximum so existing OpenTDF deployments remain unlimited by default.
type MaxObjectCounts struct {
	Namespaces                          int64 `mapstructure:"namespaces" default:"0"`
	AttributeDefinitionsPerNamespace    int64 `mapstructure:"attribute_definitions_per_namespace" default:"0"`
	AttributeValuesPerDefinition        int64 `mapstructure:"attribute_values_per_definition" default:"0"`
	ResourceMappingGroupsPerNamespace   int64 `mapstructure:"resource_mapping_groups_per_namespace" default:"0"`
	ResourceMappingsPerAttributeValue   int64 `mapstructure:"resource_mappings_per_attribute_value" default:"0"`
	SubjectMappingsPerAttributeValue    int64 `mapstructure:"subject_mappings_per_attribute_value" default:"0"`
	SubjectConditionSetsPerNamespace    int64 `mapstructure:"subject_condition_sets_per_namespace" default:"0"`
	ObligationDefinitionsPerNamespace   int64 `mapstructure:"obligation_definitions_per_namespace" default:"0"`
	ObligationValuesPerDefinition       int64 `mapstructure:"obligation_values_per_definition" default:"0"`
	ObligationTriggersPerAttributeValue int64 `mapstructure:"obligation_triggers_per_attribute_value" default:"0"`
	ActionsPerNamespace                 int64 `mapstructure:"actions_per_namespace" default:"0"`
}

func (l MaxObjectCounts) Validate() error {
	limits := map[string]int64{
		"namespaces":                              l.Namespaces,
		"attribute_definitions_per_namespace":     l.AttributeDefinitionsPerNamespace,
		"attribute_values_per_definition":         l.AttributeValuesPerDefinition,
		"resource_mapping_groups_per_namespace":   l.ResourceMappingGroupsPerNamespace,
		"resource_mappings_per_attribute_value":   l.ResourceMappingsPerAttributeValue,
		"subject_mappings_per_attribute_value":    l.SubjectMappingsPerAttributeValue,
		"subject_condition_sets_per_namespace":    l.SubjectConditionSetsPerNamespace,
		"obligation_definitions_per_namespace":    l.ObligationDefinitionsPerNamespace,
		"obligation_values_per_definition":        l.ObligationValuesPerDefinition,
		"obligation_triggers_per_attribute_value": l.ObligationTriggersPerAttributeValue,
		"actions_per_namespace":                   l.ActionsPerNamespace,
	}
	for name, limit := range limits {
		if limit < 0 {
			return fmt.Errorf("policy object limit [%s] must be zero or positive", name)
		}
	}
	return nil
}

// ObjectLimitError describes which configured object limit rejected an addition.
type ObjectLimitError struct {
	ObjectType string
	Limit      int64
	Current    int64
	Added      int64
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
		return &ObjectLimitError{
			ObjectType: objectType,
			Limit:      limit,
			Current:    current,
			Added:      int64(added),
		}
	}
	return nil
}

// ObjectLimitConnectError translates a configured limit error for the public
// service boundary and logs rejected mutations. Unrelated errors are left to
// the service's normal path.
func ObjectLimitConnectError(ctx context.Context, log *logger.Logger, operation string, err error) error {
	var limitErr *ObjectLimitError
	if !errors.As(err, &limitErr) {
		return nil
	}

	log.WarnContext(ctx, "policy object limit reached; rejected mutation",
		slog.String("operation", operation),
		slog.String("object_type", limitErr.ObjectType),
		slog.Int64("current_count", limitErr.Current),
		slog.Int64("configured_maximum", limitErr.Limit),
		slog.Int64("attempted_addition", limitErr.Added),
		slog.Bool("configured_maximum_below_current_count", limitErr.Limit < limitErr.Current),
	)
	return connect.NewError(connect.CodeResourceExhausted, err)
}
