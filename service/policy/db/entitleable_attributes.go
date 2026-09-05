package db

import (
	"context"
	"fmt"
	"strings"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/pkg/db"
)

// resolveEntitleableValueFqns preserves value lookup semantics without hydrating
// encryption policy or resource mappings that authorization never consumes.
func (c *PolicyDBClient) resolveEntitleableValueFqns(ctx context.Context, fqns []string) ([]string, map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue, error) {
	normalized := make([]string, len(fqns))
	definitionFqns := make([]string, 0, len(fqns))
	seenDefinitions := make(map[string]struct{}, len(fqns))
	requested := make(map[string]struct{}, len(fqns))
	for i, fqn := range fqns {
		fqn = strings.ToLower(fqn)
		normalized[i] = fqn
		requested[fqn] = struct{}{}
		defFqn := definitionFqnFromValueFqn(fqn)
		if _, seen := seenDefinitions[defFqn]; defFqn != "" && !seen {
			seenDefinitions[defFqn] = struct{}{}
			definitionFqns = append(definitionFqns, defFqn)
		}
	}
	rows, err := c.queries.getEntitleableAttributeValues(ctx, getEntitleableAttributeValuesParams{
		DefinitionFqns: definitionFqns,
		ValueFqns:      normalized,
	})
	if err != nil {
		return nil, nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	definitions := make(map[string]*policy.Attribute, len(definitionFqns))
	traversable := make(map[string]bool, len(definitionFqns))
	pairs := make(map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue, len(fqns))
	for _, row := range rows {
		attr, exists := definitions[row.DefinitionFqn]
		if !exists {
			attr = &policy.Attribute{
				Id: row.DefinitionID, Fqn: row.DefinitionFqn,
				Rule:      attributesRuleTypeEnumTransformOut(string(row.Rule)),
				Namespace: &policy.Namespace{Id: row.NamespaceID, Name: row.NamespaceName, Fqn: row.NamespaceFqn},
			}
			definitions[row.DefinitionFqn] = attr
			traversable[row.DefinitionFqn] = row.AllowTraversal
		}
		if row.ValueID == "" {
			continue
		}
		_, isRequested := requested[row.ValueFqn]
		if !row.ValueActive {
			if isRequested {
				return nil, nil, fmt.Errorf("value fqn [%s] inactive: %w", row.ValueFqn, db.ErrAttributeValueInactive)
			}
			continue
		}
		value := &policy.Value{Id: row.ValueID, Fqn: row.ValueFqn}
		attr.Values = append(attr.Values, value)
		if isRequested {
			pairs[row.ValueFqn] = &attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{Attribute: attr, Value: value}
		}
	}
	for _, fqn := range normalized {
		if _, found := pairs[fqn]; found {
			continue
		}
		defFqn := definitionFqnFromValueFqn(fqn)
		if traversable[defFqn] {
			pairs[fqn] = &attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{Attribute: definitions[defFqn]}
			continue
		}
		return nil, nil, fmt.Errorf("could not find value for FQN [%s]: %w", fqn, db.ErrNotFound)
	}
	return normalized, pairs, nil
}
