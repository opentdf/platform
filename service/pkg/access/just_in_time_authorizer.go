package access

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/opentdf/platform/lib/flattening"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	otdfSDK "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/pkg/access/plugin"
	policyStore "github.com/opentdf/platform/service/pkg/access/store"
	subjectmappingresolution "github.com/opentdf/platform/service/pkg/access/subject-mapping-resolution"

	"github.com/opentdf/platform/service/logger"
)

var (
	ErrMissingRequiredSDK = errors.New("access: missing required SDK")
	ErrInvalidEntityType  = errors.New("access: invalid entity type")
)

type JustInTimeAuthorizer struct {
	logger *logger.Logger
	sdk    *otdfSDK.SDK
	// embedded PDP
	pdp *PolicyDecisionPoint
	// plugin PDPs
	pluginPDPs []plugin.PolicyDecisionPoint
}

// JustInTimeAuthorizer creates a new Policy Decision Point instance with no in-memory policy and a remote connection
// via authenticated SDK, then fetches all entitlement policy from provided store interface or policy services directly.
func NewJustInTimeAuthorizer(
	ctx context.Context,
	l *logger.Logger,
	sdk *otdfSDK.SDK,
	store policyStore.EntitlementPolicyStore,
	pluginPDPs []plugin.PolicyDecisionPointConfig,
) (*JustInTimeAuthorizer, error) {
	var err error

	if sdk == nil {
		return nil, ErrMissingRequiredSDK
	}
	if l == nil {
		l, err = logger.NewLogger(defaultFallbackLoggerConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize new PDP logger and none was provided: %w", err)
		}
	}

	p := &JustInTimeAuthorizer{
		sdk:    sdk,
		logger: l,
	}

	// If no store is provided, have EntitlementPolicyRetriever fetch from policy services
	if !store.IsEnabled() || !store.IsReady(ctx) {
		l.DebugContext(ctx, "no EntitlementPolicyStore provided or not yet ready, will retrieve directly from policy services")
		store = policyStore.NewEntitlementPolicyRetriever(sdk)
	}

	allAttributes, err := store.ListAllAttributes(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list cached attributes: %w", err)
	}
	allSubjectMappings, err := store.ListAllSubjectMappings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list cached subject mappings: %w", err)
	}
	allRegisteredResources, err := store.ListAllRegisteredResources(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch all registered resources: %w", err)
	}

	pdp, err := NewPolicyDecisionPoint(ctx, l, allAttributes, allSubjectMappings, allRegisteredResources)
	if err != nil {
		return nil, fmt.Errorf("failed to create new policy decision point: %w", err)
	}
	p.pdp = pdp

	for _, pluginPDPConfig := range pluginPDPs {
		err := pluginPDPConfig.PolicyDecisionPointI.New(ctx, l, store, pluginPDPConfig.AttributePrefixes)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize plugin PDP: %w", err)
		}
		p.pluginPDPs = append(p.pluginPDPs, pluginPDPConfig.PolicyDecisionPointI)
	}
	return p, nil
}

// GetDecision retrieves the decision for the provided entity chain, action, and resources.
// It resolves the entity chain to get the entity representations and then calls the embedded PDP to get the decision.
// The decision is returned as a slice of Decision objects, along with a global boolean indicating whether or not all
// decisions are allowed.
func (p *JustInTimeAuthorizer) GetDecision(
	ctx context.Context,
	entityIdentifier *authzV2.EntityIdentifier,
	action *policy.Action,
	resources []*authzV2.Resource,
) ([]*Decision, bool, error) {
	var (
		entityRepresentations   []*entityresolutionV2.EntityRepresentation
		err                     error
		skipEnvironmentEntities = true
	)

	switch entityIdentifier.GetIdentifier().(type) {
	case *authzV2.EntityIdentifier_EntityChain:
		entityRepresentations, err = p.resolveEntitiesFromEntityChain(ctx, entityIdentifier.GetEntityChain(), skipEnvironmentEntities)

	case *authzV2.EntityIdentifier_Token:
		entityRepresentations, err = p.resolveEntitiesFromToken(ctx, entityIdentifier.GetToken(), skipEnvironmentEntities)

	case *authzV2.EntityIdentifier_RegisteredResourceValueFqn:
		regResValueFQN := strings.ToLower(entityIdentifier.GetRegisteredResourceValueFqn())
		// registered resources do not have entity representations, so only one decision to make and we can skip the remaining logic
		decision, err := p.pdp.GetDecisionRegisteredResource(ctx, regResValueFQN, action, resources)
		if err != nil {
			return nil, false, fmt.Errorf("failed to get decision for registered resource value FQN [%s]: %w", regResValueFQN, err)
		}
		if decision == nil {
			return nil, false, fmt.Errorf("decision is nil for registered resource value FQN [%s]", regResValueFQN)
		}
		return []*Decision{decision}, decision.Access, nil

	default:
		return nil, false, ErrInvalidEntityType
	}
	if err != nil {
		return nil, false, fmt.Errorf("failed to resolve entity identifier: %w", err)
	}

	var decisions []*Decision
	allPermitted := true
	for _, entityRep := range entityRepresentations {
		var d *Decision
		for _, pluginPDP := range p.pluginPDPs {
			// TODO: figure out API with multiple resources in one decision, but just strip off the first for POC
			// TODO: remove duplicate entitlement resolution logic and refactor the regular PDP to take in entitlements instead of doing this work twice
			if pluginPDP.IsValidDecisionableAction(action) && pluginPDP.IsValidDecisionableResource(resources[0]) {
				// Filter all attributes down to only those that relevant to the entitlement decisioning of these specific resources
				decisionableAttributes, err := getResourceDecisionableAttributes(ctx, p.pdp.logger, p.pdp.allRegisteredResourceValuesByFQN, p.pdp.allEntitleableAttributesByValueFQN /* action, */, resources)
				if err != nil {
					return nil, false, fmt.Errorf("error getting decisionable attributes: %w", err)
				}

				// Resolve them to their entitled FQNs and the actions available on each
				entitledFQNsToActions, err := subjectmappingresolution.EvaluateSubjectMappingsWithActions(decisionableAttributes, entityRep)
				if err != nil {
					return nil, false, fmt.Errorf("error evaluating subject mappings for entitlement: %w", err)
				}
				isAllowed, err := pluginPDP.GetDecision(ctx, entityRep, &entitledFQNsToActions, action, resources[0])
				if err != nil {
					return nil, false, fmt.Errorf("error evaluating plugin PDP %s: %w", pluginPDP.Name(), err)
				}
				d = &Decision{
					Access: isAllowed,
					Results: []ResourceDecision{
						{
							Passed:          isAllowed,
							ResourceID:      resources[0].GetEphemeralId(),
							ResourceName:    resources[0].GetRegisteredResourceValueFqn(),
							DataRuleResults: nil,
						},
					},
				}
				break
			}
		}

		if d == nil {
			d, err = p.pdp.GetDecision(ctx, entityRep, action, resources)
			if err != nil {
				return nil, false, fmt.Errorf("failed to get decision for entityRepresentation with original id [%s]: %w", entityRep.GetOriginalId(), err)
			}
		}
		if d == nil {
			return nil, false, fmt.Errorf("decision is nil: %w", err)
		}
		if !d.Access {
			allPermitted = false
		}
		// Decisions should be granular, so do not globally pass or fail
		decisions = append(decisions, d)
	}

	return decisions, allPermitted, nil
}

// GetEntitlements retrieves the entitlements for the provided entity chain.
// It resolves the entity chain to get the entity representations and then calls the embedded PDP to get the entitlements.
func (p *JustInTimeAuthorizer) GetEntitlements(
	ctx context.Context,
	entityIdentifier *authzV2.EntityIdentifier,
	withComprehensiveHierarchy bool,
) ([]*authzV2.EntityEntitlements, error) {
	p.logger.DebugContext(ctx, "getting entitlements - resolving entity chain")

	var (
		entityRepresentations   []*entityresolutionV2.EntityRepresentation
		err                     error
		skipEnvironmentEntities = false
	)

	switch entityIdentifier.GetIdentifier().(type) {
	case *authzV2.EntityIdentifier_EntityChain:
		entityRepresentations, err = p.resolveEntitiesFromEntityChain(ctx, entityIdentifier.GetEntityChain(), skipEnvironmentEntities)

	case *authzV2.EntityIdentifier_Token:
		entityRepresentations, err = p.resolveEntitiesFromToken(ctx, entityIdentifier.GetToken(), skipEnvironmentEntities)

	case *authzV2.EntityIdentifier_RegisteredResourceValueFqn:
		p.logger.DebugContext(ctx, "getting entitlements - resolving registered resource value FQN")
		regResValueFQN := strings.ToLower(entityIdentifier.GetRegisteredResourceValueFqn())
		// registered resources do not have entity representations, so we can skip the remaining logic
		return p.pdp.GetEntitlementsRegisteredResource(ctx, regResValueFQN, withComprehensiveHierarchy)

	default:
		return nil, fmt.Errorf("entity type %T: %w", entityIdentifier.GetIdentifier(), ErrInvalidEntityType)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to resolve entities from entity identifier: %w", err)
	}

	matchedSubjectMappings, err := p.getMatchedSubjectMappings(ctx, entityRepresentations)
	if err != nil {
		return nil, fmt.Errorf("failed to get matched subject mappings: %w", err)
	}
	// If no subject mappings are found, return empty entitlements
	if matchedSubjectMappings == nil {
		// TODO: is this an error case?
		p.logger.DebugContext(ctx, "matched subject mappings is empty")
		return nil, nil
	}

	entitlements, err := p.pdp.GetEntitlements(ctx, entityRepresentations, matchedSubjectMappings, withComprehensiveHierarchy)
	if err != nil {
		return nil, fmt.Errorf("failed to get entitlements: %w", err)
	}
	return entitlements, nil
}

// getMatchedSubjectMappings retrieves the subject mappings for the provided entity representations
func (p *JustInTimeAuthorizer) getMatchedSubjectMappings(
	ctx context.Context,
	entityRepresentations []*entityresolutionV2.EntityRepresentation,
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
		return nil, fmt.Errorf("failed to match subject mappings: %w", err)
	}
	return rsp.GetSubjectMappings(), nil
}

// resolveEntitiesFromEntityChain roundtrips to ERS to resolve the provided entity chain
// and optionally skips environment entities (which is expected behavior in decision flow)
func (p *JustInTimeAuthorizer) resolveEntitiesFromEntityChain(
	ctx context.Context,
	entityChain *entity.EntityChain,
	skipEnvironmentEntities bool,
) ([]*entityresolutionV2.EntityRepresentation, error) {
	p.logger.DebugContext(ctx,
		"resolving entities from entity chain",
		slog.String("entity_chain_id", entityChain.GetEphemeralId()),
		slog.Bool("skip_environment_entities", skipEnvironmentEntities),
	)

	var filteredEntities []*entity.Entity
	if skipEnvironmentEntities {
		for _, chained := range entityChain.GetEntities() {
			if chained.GetCategory() == entity.Entity_CATEGORY_ENVIRONMENT {
				continue
			}
			filteredEntities = append(filteredEntities, chained)
		}
	} else {
		filteredEntities = entityChain.GetEntities()
	}
	if len(filteredEntities) == 0 {
		return nil, errors.New("no subject entities to resolve - all were environment entities and skipped")
	}

	ersResp, err := p.sdk.EntityResolutionV2.ResolveEntities(ctx, &entityresolutionV2.ResolveEntitiesRequest{Entities: filteredEntities})
	if err != nil {
		return nil, fmt.Errorf("failed to resolve entities: %w", err)
	}
	entityRepresentations := ersResp.GetEntityRepresentations()
	if entityRepresentations == nil {
		return nil, fmt.Errorf("failed to get entity representations: %w", err)
	}
	return entityRepresentations, nil
}

// resolveEntitiesFromToken roundtrips to ERS to resolve the provided token
// and optionally skips environment entities (which is expected behavior in decision flow)
func (p *JustInTimeAuthorizer) resolveEntitiesFromToken(
	ctx context.Context,
	token *entity.Token,
	skipEnvironmentEntities bool,
) ([]*entityresolutionV2.EntityRepresentation, error) {
	// WARNING: do not log the token JWT, just its ID
	p.logger.DebugContext(ctx, "resolving entities from token", slog.String("token_ephemeral_id", token.GetEphemeralId()))
	ersResp, err := p.sdk.EntityResolutionV2.CreateEntityChainsFromTokens(ctx, &entityresolutionV2.CreateEntityChainsFromTokensRequest{Tokens: []*entity.Token{token}})
	if err != nil {
		return nil, fmt.Errorf("failed to create entity chains from token: %w", err)
	}
	entityChains := ersResp.GetEntityChains()
	if len(entityChains) != 1 {
		return nil, fmt.Errorf("received %d entity chains in ERS response but expected exactly 1", len(entityChains))
	}
	return p.resolveEntitiesFromEntityChain(ctx, entityChains[0], skipEnvironmentEntities)
}
