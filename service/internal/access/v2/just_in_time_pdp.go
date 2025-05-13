package access

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/lib/flattening"
	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	otdfSDK "github.com/opentdf/platform/sdk"

	"github.com/opentdf/platform/service/logger"
)

type JustInTimePDP struct {
	logger *logger.Logger
	sdk    *otdfSDK.SDK
	// embedded PDP
	pdp *PolicyDecisionPoint
}

// JustInTimePDP creates a new Policy Decision Point instance with no in-memory policy and a remote connection
// via authenticated SDK, then fetches all Attributes and Subject Mappings from the policy services.
func NewJustInTimePDP(
	ctx context.Context,
	l *logger.Logger,
	sdk *otdfSDK.SDK,
) (*JustInTimePDP, error) {
	var err error

	if sdk == nil {
		l.ErrorContext(ctx, "invalid arguments", slog.String("error", ErrMissingRequiredSDK.Error()))
		return nil, ErrMissingRequiredSDK
	}
	if l == nil {
		l, err = logger.NewLogger(defaultFallbackLoggerConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize new PDP logger and none was provided: %w", err)
		}
	}

	p := &JustInTimePDP{
		sdk:    sdk,
		logger: l,
	}

	allAttributes, err := p.fetchAllDefinitions(ctx)
	if err != nil {
		l.ErrorContext(ctx, "failed to fetch all attribute definitions", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to fetch all attribute definitions: %w", err)
	}
	allSubjectMappings, err := p.fetchAllSubjectMappings(ctx)
	if err != nil {
		l.ErrorContext(ctx, "failed to fetch all subject mappings", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to fetch all subject mappings: %w", err)
	}
	pdp, err := NewPolicyDecisionPoint(ctx, l, allAttributes, allSubjectMappings)
	if err != nil {
		l.ErrorContext(ctx, "failed to create new policy decision point", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to create new policy decision point: %w", err)
	}
	p.pdp = pdp
	return p, nil
}

// GetDecision retrieves the decision for the provided entity chain, action, and resources.
// It resolves the entity chain to get the entity representations and then calls the embedded PDP to get the decision.
// The decision is returned as a slice of Decision objects, along with a global boolean indicating whether or not all
// decisions are allowed.
func (p *JustInTimePDP) GetDecision(
	ctx context.Context,
	entityChain *authz.EntityChain,
	action *policy.Action,
	resources []*authz.Resource,
) ([]*Decision, bool, error) {
	p.logger.DebugContext(ctx, "getting decision - resolving entity chain")
	entityRepresentations, err := p.resolveEntities(ctx, entityChain)
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to resolve entity chain", slog.String("error", err.Error()))
		return nil, false, fmt.Errorf("failed to resolve entity chain: %w", err)
	}

	// TODO: get bulk decision (multiple entity representations) within PDP?
	// Maybe only one of the entity representations is needed... stripping off environment entities?
	decisions := make([]*Decision, len(entityRepresentations))
	allPermitted := true
	for idx, entityRep := range entityRepresentations {
		d, err := p.pdp.GetDecision(ctx, entityRep, action, resources)
		if err != nil {
			p.logger.ErrorContext(ctx, "failed to get decision", slog.String("error", err.Error()))
			return nil, false, fmt.Errorf("failed to get decision: %w", err)
		}
		if d == nil {
			p.logger.ErrorContext(ctx, "decision is nil")
			return nil, false, fmt.Errorf("decision is nil: %w", err)
		}
		if !d.Access {
			allPermitted = false
		}
		// Decisions should be granular, so do not globally pass or fail
		decisions[idx] = d
	}

	return decisions, allPermitted, nil
}

// GetEntitlements retrieves the entitlements for the provided entity chain.
// It resolves the entity chain to get the entity representations and then calls the embedded PDP to get the entitlements.
func (p *JustInTimePDP) GetEntitlements(
	ctx context.Context,
	entities []*authz.Entity,
	withComprehensiveHierarchy bool,
) ([]*authz.EntityEntitlements, error) {
	p.logger.DebugContext(ctx, "getting entitlements - resolving entity chain")

	entityChain := &authz.EntityChain{
		Entities: entities,
	}
	entityRepresentations, err := p.resolveEntities(ctx, entityChain)
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to resolve entity chain", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to resolve entity chain: %w", err)
	}

	matchedSubjectMappings, err := p.getMatchedSubjectMappings(ctx, entityRepresentations)
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to get matched subject mappings", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to get matched subject mappings: %w", err)
	}
	// If no subject mappings are found, return empty entitlements
	if matchedSubjectMappings == nil {
		p.logger.ErrorContext(ctx, "matched subject mappings is empty")
		return nil, nil
	}

	entitlements, err := p.pdp.GetEntitlements(ctx, entityRepresentations, matchedSubjectMappings, withComprehensiveHierarchy)
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to get entitlements", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to get entitlements: %w", err)
	}
	return entitlements, nil

}

// getMatchedSubjectMappings retrieves the subject mappings for the provided entity representations
func (p *JustInTimePDP) getMatchedSubjectMappings(
	ctx context.Context,
	entityRepresentations []*entityresolution.EntityRepresentation,
	// updated with the results, attrValue FQN to attribute and value with subject mappings
	// entitleableAttributes map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue,
) ([]*policy.SubjectMapping, error) {
	// Break the entity down the entities into their properties/selectors and retrieve only those subject mappings
	subjectProperties := make([]*policy.SubjectProperty, 0)
	subjectPropertySet := make(map[string]struct{})
	for _, entityRep := range entityRepresentations {
		for _, entity := range entityRep.GetAdditionalProps() {
			flattened, err := flattening.Flatten(entity.AsMap())
			if err != nil {
				p.logger.ErrorContext(ctx, "failed to flatten entity representation", slog.String("error", err.Error()))
				return nil, fmt.Errorf("failed to flatten entity representation: %w", err)
			}
			for _, item := range flattened.Items {
				if _, ok := subjectPropertySet[item.Key]; !ok {
					subjectProperties = append(subjectProperties, &policy.SubjectProperty{
						ExternalSelectorValue: item.Key,
					})
				}
			}
		}
	}

	// Greedily retrieve the filtered subject mappings that match one of the subject properties
	req := &subjectmapping.MatchSubjectMappingsRequest{
		SubjectProperties: subjectProperties,
	}
	rsp, err := p.sdk.SubjectMapping.MatchSubjectMappings(ctx, req)
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to match subject mappings", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to match subject mappings: %w", err)
	}
	return rsp.GetSubjectMappings(), nil

	// // Build the value, definition, and subject mapping combination to map under each mapped attribute value FQN
	// for _, sm := range subjectMappings.GetSubjectMappings() {
	// 	if err := validateSubjectMapping(sm); err != nil {
	// 		p.logger.ErrorContext(ctx, "subject mapping is invalid", slog.String("error", err.Error()))
	// 		return fmt.Errorf("subject mapping is invalid: %w", err)
	// 	}

	// 	mappedValue := sm.GetAttributeValue()
	// 	mappedValueFQN := mappedValue.GetFqn()

	// 	// If more than one relevant subject mapping for a value, merge existing with new
	// 	if _, ok := entitleableAttributes[mappedValueFQN]; ok {
	// 		entitleableAttributes[mappedValueFQN].Value.SubjectMappings = append(entitleableAttributes[mappedValueFQN].Value.SubjectMappings, sm)
	// 		continue
	// 	}

	// 	// Take subject mapping's attribute value and its definition from memory
	// 	parentDefinition, err := p.getDefinition(mappedValueFQN)
	// 	if err != nil {
	// 		p.logger.ErrorContext(ctx, "failed to get attribute definition", slog.String("error", err.Error()))
	// 		return fmt.Errorf("failed to get attribute definition: %w", err)
	// 	}

	// 	mappedValue.SubjectMappings = []*policy.SubjectMapping{sm}
	// 	mapped := &attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
	// 		Value:     mappedValue,
	// 		Attribute: parentDefinition,
	// 	}

	// 	entitleableAttributes[mappedValueFQN] = mapped
	// }
	// return nil
}

// fetchAllDefinitions retrieves all attribute definitions within policy
func (p *JustInTimePDP) fetchAllDefinitions(ctx context.Context) ([]*policy.Attribute, error) {
	// If quantity of attributes exceeds maximum list pagination, all are needed to determine entitlements
	var nextOffset int32
	attrsList := make([]*policy.Attribute, 0)

	for {
		listed, err := p.sdk.Attributes.ListAttributes(ctx, &attrs.ListAttributesRequest{
			State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE,
			// defer to service default for limit pagination
			Pagination: &policy.PageRequest{
				Offset: nextOffset,
			},
		})
		if err != nil {
			p.logger.ErrorContext(ctx, "failed to list attributes", slog.String("error", err.Error()))
			return nil, fmt.Errorf("failed to list attributes: %w", err)
		}

		nextOffset = listed.GetPagination().GetNextOffset()
		attrsList = append(attrsList, listed.GetAttributes()...)

		if nextOffset <= 0 {
			break
		}
	}
	return attrsList, nil
}

// fetchAllSubjectMappings retrieves all attribute values' subject mappings within policy
func (p *JustInTimePDP) fetchAllSubjectMappings(ctx context.Context) ([]*policy.SubjectMapping, error) {
	// If quantity of attributes exceeds maximum list pagination, all are needed to determine entitlements
	var nextOffset int32
	smList := make([]*policy.SubjectMapping, 0)

	for {
		listed, err := p.sdk.SubjectMapping.ListSubjectMappings(ctx, &subjectmapping.ListSubjectMappingsRequest{
			// defer to service default for limit pagination
			Pagination: &policy.PageRequest{
				Offset: nextOffset,
			},
		})
		if err != nil {
			p.logger.ErrorContext(ctx, "failed to list attributes", slog.String("error", err.Error()))
			return nil, fmt.Errorf("failed to list attributes: %w", err)
		}

		nextOffset = listed.GetPagination().GetNextOffset()
		smList = append(smList, listed.GetSubjectMappings()...)

		if nextOffset <= 0 {
			break
		}
	}
	return smList, nil
}

// resolveEntities roundtrips to ERS to resolve the provided entity chain.
func (p *JustInTimePDP) resolveEntities(ctx context.Context, entityChain *authz.EntityChain) ([]*entityresolution.EntityRepresentation, error) {
	ersResp, err := p.sdk.EntityResoution.ResolveEntities(ctx, &entityresolution.ResolveEntitiesRequest{EntitiesV2: entityChain.GetEntities()})
	if err != nil {
		return nil, fmt.Errorf("failed to resolve entities: %w", err)
	}
	entityRepresentations := ersResp.GetEntityRepresentations()
	if entityRepresentations == nil {
		return nil, fmt.Errorf("failed to get entity representations: %w", err)
	}
	return entityRepresentations, nil
}
