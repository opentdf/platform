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
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/opentdf/platform/service/internal/access/v2/obligations"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
)

var (
	ErrMissingRequiredSDK                       = errors.New("access: missing required SDK")
	ErrInvalidEntityType                        = errors.New("access: invalid entity type")
	ErrFailedToWithRequestTokenEntityIdentifier = errors.New("access: failed to use request token as entity identifier - none found in context")
	ErrInvalidWithRequestTokenEntityIdentifier  = errors.New("access: invalid use request token as entity identifier - must be true if provided")

	requestAuthTokenEphemeralID = "with-request-token-auth-entity"
)

type JustInTimePDP struct {
	logger *logger.Logger
	sdk    *otdfSDK.SDK
	// embedded entitlement PDP
	pdp *PolicyDecisionPoint
	// embedded obligations PDP
	obligationsPDP *obligations.ObligationsPolicyDecisionPoint
}

// JustInTimePDP creates a new Policy Decision Point instance with no in-memory policy and a remote connection
// via authenticated SDK, then fetches all entitlement policy from provided store interface or policy services directly.
func NewJustInTimePDP(
	ctx context.Context,
	log *logger.Logger,
	sdk *otdfSDK.SDK,
	store EntitlementPolicyStore,
) (*JustInTimePDP, error) {
	var err error

	if sdk == nil {
		return nil, ErrMissingRequiredSDK
	}
	if log == nil {
		log, err = logger.NewLogger(defaultFallbackLoggerConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize new PDP logger and none was provided: %w", err)
		}
	}

	p := &JustInTimePDP{
		sdk:    sdk,
		logger: log,
	}

	// If no store is provided, have EntitlementPolicyRetriever fetch from policy services
	if !store.IsEnabled() || !store.IsReady(ctx) {
		log.DebugContext(ctx, "no EntitlementPolicyStore provided or not yet ready, will retrieve directly from policy services")
		store = NewEntitlementPolicyRetriever(sdk)
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
	allObligations, err := store.ListAllObligations(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch all obligations: %w", err)
	}

	pdp, err := NewPolicyDecisionPoint(ctx, log, allAttributes, allSubjectMappings, allRegisteredResources)
	if err != nil {
		return nil, fmt.Errorf("failed to create new policy decision point: %w", err)
	}
	p.pdp = pdp

	obligationsPDP, err := obligations.NewObligationsPolicyDecisionPoint(
		ctx,
		log,
		pdp.allEntitleableAttributesByValueFQN,
		pdp.allRegisteredResourceValuesByFQN,
		allObligations,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create new obligations policy decision point: %w", err)
	}
	p.obligationsPDP = obligationsPDP

	return p, nil
}

// GetDecision retrieves the decision for the provided entity identifier, action, and resources.
//
// Obligations are not entity-driven, so the actions, attributes, and decision request context are checked against
// Policy to determine which are triggered. The triggered obligations are compared against those the caller (PEP)
// reports that it can fulfill to ensure all can be satisfied.
//
// Then, it resolves the Entity Identifier into either the Registered Resource or a Token/Entity Chain and roundtrips to ERS
// for their representations. In the case of multiple entity representations, multiple decisions are returned (one per entity).
//
// The result is a list of Decision objects (one per entity), along with a global boolean indicating whether or not all
// decisions were to permit: full entitlement + all triggered obligations fulfillable.
//
// | Entity entitled | Triggered obligations are fulfillable | Decision |  Required Obligations Returned |
// | --------------- | ------------------------------------- | -------- | ------------------------------ |
// | Yes             | Yes								     | Permit   | Yes                            |
// | Yes             | No							         | Deny     | Yes (allows corrective action) |
// | No              | Yes							         | Deny     | No                             |
// | No              | No							         | Deny     | No                             |
func (p *JustInTimePDP) GetDecision(
	ctx context.Context,
	entityIdentifier *authzV2.EntityIdentifier,
	action *policy.Action,
	resources []*authzV2.Resource,
	requestContext *policy.RequestContext,
	fulfillableObligationValueFQNs []string,
) ([]*Decision, bool, error) {
	var (
		entityRepresentations   []*entityresolutionV2.EntityRepresentation
		err                     error
		skipEnvironmentEntities = true
	)

	// Because there are three possible types of entities, check obligations first to more easily handle decisioning logic
	obligationDecision, err := p.obligationsPDP.GetAllTriggeredObligationsAreFulfilled(
		ctx,
		resources,
		action,
		requestContext,
		fulfillableObligationValueFQNs,
	)
	if err != nil {
		return nil, false, fmt.Errorf("failed to check obligations: %w", err)
	}

	switch entityIdentifier.GetIdentifier().(type) {
	case *authzV2.EntityIdentifier_EntityChain:
		entityRepresentations, err = p.resolveEntitiesFromEntityChain(ctx, entityIdentifier.GetEntityChain(), skipEnvironmentEntities)

	case *authzV2.EntityIdentifier_Token:
		entityRepresentations, err = p.resolveEntitiesFromToken(ctx, entityIdentifier.GetToken(), skipEnvironmentEntities)

	case *authzV2.EntityIdentifier_WithRequestToken:
		entityRepresentations, err = p.resolveEntitiesFromRequestToken(ctx, entityIdentifier.GetWithRequestToken(), skipEnvironmentEntities)

	case *authzV2.EntityIdentifier_RegisteredResourceValueFqn:
		regResValueFQN := strings.ToLower(entityIdentifier.GetRegisteredResourceValueFqn())
		// Registered resources do not have entity representations, so only one decision is made
		decision, entitlements, err := p.pdp.GetDecisionRegisteredResource(ctx, regResValueFQN, action, resources)
		if err != nil {
			return nil, false, fmt.Errorf("failed to get decision for registered resource value FQN [%s]: %w", regResValueFQN, err)
		}
		if decision == nil {
			return nil, false, fmt.Errorf("decision is nil for registered resource value FQN [%s]", regResValueFQN)
		}

		// Update resource decisions with obligations and set final access decision
		hasRequiredObligations := len(obligationDecision.RequiredObligationValueFQNs) > 0
		if decision.Access && hasRequiredObligations {
			// Access should only be granted if entitled AND obligations fulfilled
			decision.Access = obligationDecision.AllObligationsSatisfied
		}

		// Propagate obligations within policy on each resource decision object
		for idx := range decision.Results {
			resourceDecision := decision.Results[idx]

			if hasRequiredObligations {
				// Update with specific obligation data from the obligations PDP
				perResource := obligationDecision.RequiredObligationValueFQNsPerResource[idx]
				resourceDecision.ObligationsSatisfied = perResource.ObligationsSatisfied
				resourceDecision.RequiredObligationValueFQNs = perResource.RequiredObligationValueFQNs
			} else {
				// No required obligations means all obligations are satisfied
				resourceDecision.ObligationsSatisfied = true
			}

			resourceDecision.Passed = resourceDecision.Entitled && resourceDecision.ObligationsSatisfied
			decision.Results[idx] = resourceDecision
		}

		p.auditDecision(ctx, regResValueFQN, action, decision, entitlements, fulfillableObligationValueFQNs, obligationDecision)
		return []*Decision{decision}, decision.Access, nil

	default:
		return nil, false, ErrInvalidEntityType
	}
	if err != nil {
		return nil, false, fmt.Errorf("failed to resolve entity identifier: %w", err)
	}

	// Make initial entitlement decisions
	entityDecisions := make([]*Decision, len(entityRepresentations))
	entityEntitlements := make([]map[string][]*policy.Action, len(entityRepresentations))
	allPermitted := true
	for idx, entityRep := range entityRepresentations {
		d, entitlements, err := p.pdp.GetDecision(ctx, entityRep, action, resources)
		if err != nil {
			return nil, false, fmt.Errorf("failed to get decision for entityRepresentation with original id [%s]: %w", entityRep.GetOriginalId(), err)
		}
		if d == nil {
			return nil, false, fmt.Errorf("decision is nil: %w", err)
		}
		if !d.Access {
			allPermitted = false
		}
		entityDecisions[idx] = d
		entityEntitlements[idx] = entitlements
	}

	// Update resource decisions with obligations and set final access decision
	hasRequiredObligations := len(obligationDecision.RequiredObligationValueFQNs) > 0
	if allPermitted && hasRequiredObligations {
		// Only grant access if entitled AND obligations fulfilled
		allPermitted = obligationDecision.AllObligationsSatisfied
	}

	// Propagate obligations within policy on each resource decision object
	for entityIdx, decision := range entityDecisions {
		for idx := range decision.Results {
			resourceDecision := decision.Results[idx]

			if hasRequiredObligations {
				// Update with specific obligation data from the obligations PDP
				perResource := obligationDecision.RequiredObligationValueFQNsPerResource[idx]
				resourceDecision.ObligationsSatisfied = perResource.ObligationsSatisfied
				resourceDecision.RequiredObligationValueFQNs = perResource.RequiredObligationValueFQNs
			} else {
				// No required obligations means all obligations are satisfied
				resourceDecision.ObligationsSatisfied = true
			}

			resourceDecision.Passed = resourceDecision.Entitled && resourceDecision.ObligationsSatisfied
			decision.Results[idx] = resourceDecision
		}

		decision.Access = allPermitted
		entityRepID := entityRepresentations[entityIdx].GetOriginalId()
		p.auditDecision(ctx, entityRepID, action, decision, entityEntitlements[entityIdx], fulfillableObligationValueFQNs, obligationDecision)
	}

	return entityDecisions, allPermitted, nil
}

// GetEntitlements retrieves the entitlements for the provided entity chain.
// It resolves the entity chain to get the entity representations and then calls the embedded PDP to get the entitlements.
func (p *JustInTimePDP) GetEntitlements(
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

	case *authzV2.EntityIdentifier_WithRequestToken:
		entityRepresentations, err = p.resolveEntitiesFromRequestToken(ctx, entityIdentifier.GetWithRequestToken(), skipEnvironmentEntities)

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
func (p *JustInTimePDP) getMatchedSubjectMappings(
	ctx context.Context,
	entityRepresentations []*entityresolutionV2.EntityRepresentation,
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
func (p *JustInTimePDP) resolveEntitiesFromEntityChain(
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
func (p *JustInTimePDP) resolveEntitiesFromToken(
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

// resolveEntitiesFromRequestToken pulls the request token off the context where it has been set upstream
// by an interceptor and builds an entity.Token that it then resolves
func (p *JustInTimePDP) resolveEntitiesFromRequestToken(
	ctx context.Context,
	withRequestToken *wrapperspb.BoolValue,
	skipEnvironmentEntities bool,
) ([]*entityresolutionV2.EntityRepresentation, error) {
	if !withRequestToken.GetValue() {
		return nil, ErrInvalidWithRequestTokenEntityIdentifier
	}
	rawToken := ctxAuth.GetRawAccessTokenFromContext(ctx, p.logger)
	if rawToken == "" {
		return nil, ErrFailedToWithRequestTokenEntityIdentifier
	}
	token := &entity.Token{
		Jwt:         rawToken,
		EphemeralId: requestAuthTokenEphemeralID,
	}

	return p.resolveEntitiesFromToken(ctx, token, skipEnvironmentEntities)
}

// auditDecision logs a GetDecisionV2 audit event with obligation information
func (p *JustInTimePDP) auditDecision(
	ctx context.Context,
	entityID string,
	action *policy.Action,
	decision *Decision,
	entitlements map[string][]*policy.Action,
	fulfillableObligationValueFQNs []string,
	obligationDecision obligations.ObligationPolicyDecision,
) {
	// Determine audit decision result
	auditDecision := audit.GetDecisionResultDeny
	if decision.Access {
		auditDecision = audit.GetDecisionResultPermit
	}

	p.logger.Audit.GetDecisionV2(ctx, audit.GetDecisionV2EventParams{
		EntityID:                       entityID,
		ActionName:                     action.GetName(),
		Decision:                       auditDecision,
		Entitlements:                   entitlements,
		FulfillableObligationValueFQNs: fulfillableObligationValueFQNs,
		ObligationsSatisfied:           obligationDecision.AllObligationsSatisfied,
		ResourceDecisions:              decision.Results,
	})
}
