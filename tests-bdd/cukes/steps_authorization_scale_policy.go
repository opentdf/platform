package cukes

import (
	"context"
	"fmt"
	"strings"

	"github.com/cucumber/godog"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
)

func createScaleAttributes(ctx context.Context, namespaceRef string, table *godog.Table) (context.Context, error) {
	rows, err := scaleTableRows(table, "attribute", "rule", valuesKey)
	if err != nil {
		return ctx, err
	}
	scenario := GetPlatformScenarioContext(ctx)
	namespace, ok := scenario.GetObject(namespaceRef).(string)
	if !ok {
		return ctx, fmt.Errorf("missing namespace %q", namespaceRef)
	}
	for _, row := range rows {
		rule, err := parseAttributeRule(row[1])
		if err != nil {
			return ctx, err
		}
		values := strings.Split(row[2], ",")
		for i := range values {
			values[i] = strings.TrimSpace(values[i])
		}
		response, err := scenario.SDK.Attributes.CreateAttribute(ctx, &attributes.CreateAttributeRequest{NamespaceId: namespace, Name: row[0], Rule: rule, Values: values})
		if err != nil {
			return ctx, err
		}
		if response.GetAttribute().GetId() == "" {
			return ctx, fmt.Errorf("attribute %s returned no identity", row[0])
		}
		scenario.RecordObject(row[0], response.GetAttribute())
	}
	return ctx, nil
}

func scaleAttributeValue(scenario *PlatformScenarioContext, reference string) (*policy.Value, string, error) {
	attributeRef, valueName, ok := strings.Cut(strings.TrimSpace(reference), "/")
	if !ok {
		return nil, "", fmt.Errorf("expected attribute/value, got %q", reference)
	}
	attribute, ok := scenario.GetObject(attributeRef).(*policy.Attribute)
	if ok && attribute.GetFqn() != "" {
		for _, value := range attribute.GetValues() {
			if value.GetValue() == valueName {
				return value, attribute.GetFqn() + "/value/" + valueName, nil
			}
		}
	}
	return nil, "", fmt.Errorf("unknown attribute value %q", reference)
}

func createScaleGrants(ctx context.Context, table *godog.Table) (context.Context, error) {
	rows, err := scaleTableRows(table, "attribute value", "selector", "matches", "actions")
	if err != nil {
		return ctx, err
	}
	scenario := GetPlatformScenarioContext(ctx)
	for _, row := range rows {
		value, _, err := scaleAttributeValue(scenario, row[0])
		if err != nil {
			return ctx, err
		}
		response, err := scenario.SDK.SubjectMapping.CreateSubjectMapping(ctx, &subjectmapping.CreateSubjectMappingRequest{
			AttributeValueId: value.GetId(), Actions: GetActionsFromValues(&row[3], nil),
			NewSubjectConditionSet: &subjectmapping.SubjectConditionSetCreate{SubjectSets: []*policy.SubjectSet{{
				ConditionGroups: []*policy.ConditionGroup{{
					BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR,
					Conditions:      []*policy.Condition{{SubjectExternalSelectorValue: row[1], Operator: policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN, SubjectExternalValues: strings.Split(row[2], ",")}},
				}},
			}}},
		})
		if err != nil {
			return ctx, err
		}
		if response.GetSubjectMapping().GetId() == "" {
			return ctx, fmt.Errorf("grant for %s returned no identity", row[0])
		}
		if err := validateScaleMappingActions(response.GetSubjectMapping().GetActions(), row[3]); err != nil {
			return ctx, fmt.Errorf("grant for %s: %w", row[0], err)
		}
	}
	return ctx, nil
}

func defineScaleResources(ctx context.Context, table *godog.Table) (context.Context, error) {
	rows, err := scaleTableRows(table, "resource", "attributes")
	if err != nil {
		return ctx, err
	}
	scenario := GetPlatformScenarioContext(ctx)
	names := make(map[string]bool)
	for _, row := range rows {
		if names[row[0]] {
			return ctx, fmt.Errorf("duplicate resource %q", row[0])
		}
		names[row[0]] = true
		var fqns []string
		for _, reference := range strings.Split(row[1], ",") {
			_, fqn, err := scaleAttributeValue(scenario, reference)
			if err != nil {
				return ctx, err
			}
			fqns = append(fqns, fqn)
		}
		scenario.RecordObject("scale-resource/"+row[0], fqns)
	}
	return ctx, nil
}
