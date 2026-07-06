package db

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/opentdf/platform/lib/identifier"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/service/pkg/db"
)

// AttrFqnReindex will reindex all namespace, attribute, and attribute_value FQNs
func (c *PolicyDBClient) AttrFqnReindex(ctx context.Context) (res struct { //nolint:nonamedreturns // Used to initialize an anonymous struct
	Namespaces []struct {
		ID  string
		Fqn string
	}
	Attributes []struct {
		ID  string
		Fqn string
	}
	Values []struct {
		ID  string
		Fqn string
	}
},
) {
	// Get all namespaces
	ns, err := c.ListNamespaces(ctx, &namespaces.ListNamespacesRequest{
		State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
	})
	if err != nil {
		panic(fmt.Errorf("could not get namespaces: %w", err))
	}

	// Reindex all namespaces
	reindexedRecords := []upsertAttributeNamespaceFqnRow{}
	for _, n := range ns.GetNamespaces() {
		rows, err := c.queries.upsertAttributeNamespaceFqn(ctx, n.GetId())
		if err != nil {
			panic(fmt.Errorf("could not update namespace [%s] FQN: %w", n.GetId(), err))
		}
		reindexedRecords = append(reindexedRecords, rows...)
	}

	for _, r := range reindexedRecords {
		switch {
		case r.AttributeID == "" && r.ValueID == "":
			// namespace record
			res.Namespaces = append(res.Namespaces, struct {
				ID  string
				Fqn string
			}{ID: r.NamespaceID, Fqn: r.Fqn})
		case r.ValueID == "":
			// attribute definition record
			res.Attributes = append(res.Attributes, struct {
				ID  string
				Fqn string
			}{ID: r.AttributeID, Fqn: r.Fqn})
		default:
			// attribute value record
			res.Values = append(res.Values, struct {
				ID  string
				Fqn string
			}{ID: r.ValueID, Fqn: r.Fqn})
		}
	}

	return res
}

func (c *PolicyDBClient) GetAttributesByValueFqns(ctx context.Context, r *attributes.GetAttributeValuesByFqnsRequest) (map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue, error) {
	fqns := r.GetFqns()

	ctx, span := c.Start(ctx, "DB:GetAttributesByValueFqns")
	defer span.End()

	list := make(map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue, len(fqns))
	definitionFqns := make(map[string]string)
	queryFqnsSet := make(map[string]struct{}, len(fqns))

	for i, fqn := range fqns {
		// normalize to lower case
		fqn = strings.ToLower(fqn)

		// update array with normalized FQN
		fqns[i] = fqn

		// prepopulate response map for easy lookup
		list[fqn] = nil

		queryFqnsSet[fqn] = struct{}{}
		if defFqn := definitionFqnFromValueFqn(fqn); defFqn != "" {
			definitionFqns[fqn] = defFqn
			queryFqnsSet[defFqn] = struct{}{}
		}
	}

	queryFqns := make([]string, 0, len(queryFqnsSet))
	for fqn := range queryFqnsSet {
		queryFqns = append(queryFqns, fqn)
	}

	// get all attributes by value or definition FQN
	attrs, err := c.ListAttributesByFqns(ctx, queryFqns, true)
	if err != nil {
		return nil, err
	}

	defByFqn := make(map[string]*policy.Attribute, len(attrs))

	// loop through attributes to find values that match the requested FQNs
	for _, attr := range attrs {
		if attr == nil {
			continue
		}

		values := attr.GetValues()
		// Ensure that only active values are within the attribute object
		activeValues := make([]*policy.Value, 0)
		for _, val := range values {
			valFqn := val.GetFqn()
			isActive := val.GetActive().GetValue()
			if isActive {
				activeValues = append(activeValues, val)
			}
			if _, ok := list[valFqn]; ok {
				if !isActive {
					return nil, fmt.Errorf("value fqn [%s] inactive: %w", valFqn, db.ErrAttributeValueInactive)
				}
				// update response map with attribute and value pair if value FQN found
				list[valFqn] = &attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{
					Attribute: attr,
					Value:     val,
				}
			}
		}

		if len(activeValues) != len(values) {
			attr.Values = activeValues
		}

		if attr.GetFqn() != "" {
			defByFqn[attr.GetFqn()] = attr
		}
	}

	// if value is missing, attempt to resolve the attribute definition
	for valueFqn, defFqn := range definitionFqns {
		if list[valueFqn] != nil {
			continue
		}
		if attr, ok := defByFqn[defFqn]; ok {
			if attr.GetAllowTraversal().GetValue() {
				c.logger.DebugContext(ctx, "value missing but allow_traversal is true, using definition",
					slog.String("value_fqn", valueFqn),
					slog.String("def_fqn", attr.GetFqn()))
				list[valueFqn] = &attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{
					Attribute: attr,
				}
			}
		}
	}

	// Map and Merge Grants & Keys
	for vfqn, pair := range list {
		if pair == nil {
			c.logger.DebugContext(ctx, "unknown fqn - no definition for value", slog.String("fqn", vfqn))
			continue
		}

		attrGrants, err := mapKasKeysToGrants(pair.GetAttribute().GetKasKeys(), pair.GetAttribute().GetGrants(), c.logger)
		if err != nil {
			return nil, fmt.Errorf("could not map & merge attribute grants and keys: %w", err)
		}
		pair.GetAttribute().Grants = attrGrants

		if pair.GetValue() != nil {
			valGrants, err := mapKasKeysToGrants(pair.GetValue().GetKasKeys(), pair.GetValue().GetGrants(), c.logger)
			if err != nil {
				return nil, fmt.Errorf("could not map & merge value grants and keys: %w", err)
			}
			pair.GetValue().Grants = valGrants
		}

		nsGrants, err := mapKasKeysToGrants(pair.GetAttribute().GetNamespace().GetKasKeys(), pair.GetAttribute().GetNamespace().GetGrants(), c.logger)
		if err != nil {
			return nil, fmt.Errorf("could not map & merge namespace grants and keys: %w", err)
		}
		pair.GetAttribute().GetNamespace().Grants = nsGrants
	}

	// check if all requested FQNs were found
	for fqn, pair := range list {
		if pair == nil {
			return nil, fmt.Errorf("could not find value for FQN [%s]: %w", fqn, db.ErrNotFound)
		}
	}

	return list, nil
}

// resolveValueFqns normalizes the requested FQNs, resolves them via
// GetAttributesByValueFqns, and rejects any FQN that resolved only to a
// definition (nil value, which GetAttributesByValueFqns returns when a value is
// missing and allow_traversal is enabled). These value-FQN APIs require a
// concrete value per requested FQN. Returns the normalized FQNs and the resolved
// pairs.
func (c *PolicyDBClient) resolveValueFqns(ctx context.Context, fqns []string) ([]string, map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue, error) {
	normalized := make([]string, len(fqns))
	for i, fqn := range fqns {
		normalized[i] = strings.ToLower(fqn)
	}

	pairs, err := c.GetAttributesByValueFqns(ctx, &attributes.GetAttributeValuesByFqnsRequest{Fqns: normalized})
	if err != nil {
		return nil, nil, err
	}
	for fqn, pair := range pairs {
		if pair.GetValue() == nil {
			return nil, nil, fmt.Errorf("could not find value for FQN [%s]: %w", fqn, db.ErrNotFound)
		}
	}
	return normalized, pairs, nil
}

// GetKeyMappingsByFqns returns, for each requested attribute value FQN, the
// governing attribute rule and the effective KAS keys needed to build key
// splits. Keys are resolved with value > definition > namespace precedence,
// preferring the mapped key model (SimpleKasKey) but falling back to legacy
// KeyAccessServer grants at each level, mirroring the client-side granter
// resolution. Grants without a usable cached public key (missing kid/pem) yield
// no key for that level.
func (c *PolicyDBClient) GetKeyMappingsByFqns(ctx context.Context, r *attributes.GetKeyMappingsByFqnsRequest) (map[string]*attributes.GetKeyMappingsByFqnsResponse_AttributeKeyMapping, error) {
	ctx, span := c.Start(ctx, "DB:GetKeyMappingsByFqns")
	defer span.End()

	fqns := r.GetFqns()
	if len(fqns) == 0 {
		return map[string]*attributes.GetKeyMappingsByFqnsResponse_AttributeKeyMapping{}, nil
	}

	_, pairs, err := c.resolveValueFqns(ctx, fqns)
	if err != nil {
		return nil, err
	}

	mappings := make(map[string]*attributes.GetKeyMappingsByFqnsResponse_AttributeKeyMapping, len(pairs))
	for fqn, pair := range pairs {
		attr := pair.GetAttribute()
		mappings[fqn] = &attributes.GetKeyMappingsByFqnsResponse_AttributeKeyMapping{
			Rule: attr.GetRule(),
			Keys: resolveEffectiveKasKeys(pair.GetValue(), attr),
		}
	}

	return mappings, nil
}

// GetEntitleableAttributesByFqns returns, for each requested attribute value FQN,
// the information needed to resolve entitlements: the attribute rule, the value
// identity, the definition's ordered value FQNs (for hierarchy rule logic), and
// the value-level subject mappings. It runs two selective queries: the attribute
// FQN lookup for rule/value/sibling data, and a single subject-mapping-by-FQN
// query, avoiding the full-policy load used by the entitlement path today.
func (c *PolicyDBClient) GetEntitleableAttributesByFqns(ctx context.Context, r *attributes.GetEntitleableAttributesByFqnsRequest) (*attributes.GetEntitleableAttributesByFqnsResponse, error) {
	ctx, span := c.Start(ctx, "DB:GetEntitleableAttributesByFqns")
	defer span.End()

	fqns := r.GetFqns()
	if len(fqns) == 0 {
		return &attributes.GetEntitleableAttributesByFqnsResponse{
			Definitions:              map[string]*attributes.GetEntitleableAttributesByFqnsResponse_EntitleableDefinition{},
			FqnEntitleableAttributes: map[string]*attributes.GetEntitleableAttributesByFqnsResponse_EntitleableAttribute{},
		}, nil
	}
	normalized, pairs, err := c.resolveValueFqns(ctx, fqns)
	if err != nil {
		return nil, err
	}

	// Build the subject-mapping fetch set: the requested value FQNs plus, for every
	// hierarchy definition referenced, all of its value FQNs (so the hierarchy
	// siblings' subject mappings are available for entitlement propagation).
	smFetchSet := make(map[string]struct{}, len(normalized))
	for _, fqn := range normalized {
		smFetchSet[fqn] = struct{}{}
	}
	for _, pair := range pairs {
		attr := pair.GetAttribute()
		if attr.GetRule() != policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY {
			continue
		}
		for _, v := range attr.GetValues() {
			smFetchSet[v.GetFqn()] = struct{}{}
		}
	}
	smFetchFqns := make([]string, 0, len(smFetchSet))
	for fqn := range smFetchSet {
		smFetchFqns = append(smFetchFqns, fqn)
	}

	// Fetch the value-level subject mappings in one query, grouped by value FQN.
	smRows, err := c.queries.getSubjectMappingsByValueFqns(ctx, smFetchFqns)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	subjectMappingsByFqn := make(map[string][]*policy.SubjectMapping, len(smRows))
	for _, row := range smRows {
		sm, err := hydrateSubjectMappingForEntitlement(row)
		if err != nil {
			return nil, err
		}
		subjectMappingsByFqn[row.ValueFqn] = append(subjectMappingsByFqn[row.ValueFqn], sm)
	}

	entitleableValue := func(fqn, valueID string) *attributes.GetEntitleableAttributesByFqnsResponse_EntitleableValue {
		return &attributes.GetEntitleableAttributesByFqnsResponse_EntitleableValue{
			Fqn:             fqn,
			ValueId:         valueID,
			SubjectMappings: subjectMappingsByFqn[fqn],
		}
	}

	rsp := &attributes.GetEntitleableAttributesByFqnsResponse{
		Definitions:              make(map[string]*attributes.GetEntitleableAttributesByFqnsResponse_EntitleableDefinition, len(pairs)),
		FqnEntitleableAttributes: make(map[string]*attributes.GetEntitleableAttributesByFqnsResponse_EntitleableAttribute, len(pairs)),
	}

	for fqn, pair := range pairs {
		attr := pair.GetAttribute()
		defFqn := attr.GetFqn()

		// One definition entry per referenced definition. For hierarchy, carry the
		// ordered values with their subject mappings; for any_of/all_of, leave empty.
		if _, ok := rsp.GetDefinitions()[defFqn]; !ok {
			def := &attributes.GetEntitleableAttributesByFqnsResponse_EntitleableDefinition{
				Rule: attr.GetRule(),
			}
			if attr.GetRule() == policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY {
				def.Values = make([]*attributes.GetEntitleableAttributesByFqnsResponse_EntitleableValue, 0, len(attr.GetValues()))
				for _, v := range attr.GetValues() {
					def.Values = append(def.Values, entitleableValue(v.GetFqn(), v.GetId()))
				}
			}
			rsp.Definitions[defFqn] = def
		}

		rsp.FqnEntitleableAttributes[fqn] = &attributes.GetEntitleableAttributesByFqnsResponse_EntitleableAttribute{
			DefinitionFqn: defFqn,
			Value:         entitleableValue(fqn, pair.GetValue().GetId()),
		}
	}

	return rsp, nil
}

// hydrateSubjectMappingForEntitlement converts a getSubjectMappingsByValueFqns
// row into a policy.SubjectMapping, mirroring the hydration in ListSubjectMappings.
func hydrateSubjectMappingForEntitlement(row getSubjectMappingsByValueFqnsRow) (*policy.SubjectMapping, error) {
	metadata := &common.Metadata{}
	if err := unmarshalMetadata(row.Metadata, metadata); err != nil {
		return nil, err
	}

	av := &policy.Value{}
	if err := unmarshalAttributeValue(row.AttributeValue, av); err != nil {
		return nil, err
	}

	// standard_actions / custom_actions are selected as ::jsonb, so sqlc yields raw
	// []byte that unmarshalAllActionsProto consumes directly (no json.Marshal round-trip).
	actions := []*policy.Action{}
	if err := unmarshalAllActionsProto(row.StandardActions, row.CustomActions, &actions); err != nil {
		return nil, err
	}

	scs := policy.SubjectConditionSet{}
	if err := unmarshalSubjectConditionSet(row.SubjectConditionSet, &scs); err != nil {
		return nil, err
	}

	// The subject mapping's own namespace is needed for strict namespaced-mode
	// entitlement filtering in the PDP (NewPolicyDecisionPoint reads sm.Namespace).
	namespace, err := hydrateNamespaceFromInterface(row.Namespace)
	if err != nil {
		return nil, err
	}

	return &policy.SubjectMapping{
		Id:                  row.ID,
		Metadata:            metadata,
		AttributeValue:      av,
		SubjectConditionSet: &scs,
		Actions:             actions,
		Namespace:           namespace,
	}, nil
}

// resolveEffectiveKasKeys returns the most-specific effective keys for a value
// with value > definition > namespace precedence. Within a level, mapped keys
// (kas_keys) are preferred; if a level has none, its legacy KAS grants are
// converted to keys. Resolution stops at the first level that yields any key, so
// grant-configured policy resolves the same way the client granter did before.
func resolveEffectiveKasKeys(value *policy.Value, attr *policy.Attribute) []*policy.SimpleKasKey {
	if keys := value.GetKasKeys(); len(keys) > 0 {
		return keys
	}
	if keys := grantsToSimpleKasKeys(value.GetGrants()); len(keys) > 0 {
		return keys
	}
	if keys := attr.GetKasKeys(); len(keys) > 0 {
		return keys
	}
	if keys := grantsToSimpleKasKeys(attr.GetGrants()); len(keys) > 0 {
		return keys
	}
	if keys := attr.GetNamespace().GetKasKeys(); len(keys) > 0 {
		return keys
	}
	if keys := grantsToSimpleKasKeys(attr.GetNamespace().GetGrants()); len(keys) > 0 {
		return keys
	}
	return nil
}

func definitionFqnFromValueFqn(valueFqn string) string {
	httpPrefix := "http://"
	httpsPrefix := "https://"
	hadHTTP := strings.HasPrefix(valueFqn, httpPrefix)
	if hadHTTP {
		valueFqn = httpsPrefix + strings.TrimPrefix(valueFqn, httpPrefix)
	}
	parsed, err := identifier.Parse[*identifier.FullyQualifiedAttribute](valueFqn)
	if err != nil {
		return ""
	}
	if parsed.Value == "" {
		return ""
	}
	parsed.Value = ""
	defFqn := parsed.FQN()
	if hadHTTP {
		defFqn = httpPrefix + strings.TrimPrefix(defFqn, httpsPrefix)
	}
	return defFqn
}
