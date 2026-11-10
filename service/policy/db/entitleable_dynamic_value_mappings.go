package db

import (
	"context"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/pkg/db"
)

func (c *PolicyDBClient) addEntitleableDynamicValueMappings(ctx context.Context, rsp *attributes.GetEntitleableAttributesByFqnsResponse) error {
	fqns := make([]string, 0, len(rsp.GetDefinitions()))
	for fqn := range rsp.GetDefinitions() {
		fqns = append(fqns, fqn)
	}
	if len(fqns) == 0 {
		return nil
	}
	rows, err := c.queries.getDynamicValueMappingsByDefinitionFqns(ctx, fqns)
	if err != nil {
		return db.WrapIfKnownInvalidQueryErr(err)
	}
	for _, row := range rows {
		actions := []*policy.Action{}
		if err := unmarshalActionsProto(row.Actions, &actions); err != nil {
			return err
		}
		namespace, err := hydrateNamespaceFromInterface(row.Namespace)
		if err != nil {
			return err
		}
		var gate *policy.SubjectConditionSet
		if len(row.SubjectConditionSet) > 0 {
			gate = &policy.SubjectConditionSet{}
			if err := unmarshalSubjectConditionSet(row.SubjectConditionSet, gate); err != nil {
				return err
			}
		}
		def := rsp.GetDefinitions()[row.DefinitionFqn]
		def.DynamicValueMappings = append(def.DynamicValueMappings, &policy.DynamicValueMapping{
			Id: row.ID,
			AttributeDefinition: &policy.Attribute{
				Fqn: row.DefinitionFqn, Rule: def.GetRule(), Namespace: def.GetNamespace(),
			},
			ValueResolver: &policy.DynamicValueResolver{
				SubjectExternalSelectorValue: row.SubjectExternalSelectorValue,
				Operator:                     policy.SubjectMappingOperatorEnum(row.Operator),
			},
			Actions: actions, Namespace: namespace, SubjectConditionSet: gate,
		})
	}
	return nil
}
