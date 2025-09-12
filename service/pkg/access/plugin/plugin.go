package plugin

import (
	"context"

	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	ersV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	policy "github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
	policyStore "github.com/opentdf/platform/service/pkg/access/store"
	subjectmappingresolution "github.com/opentdf/platform/service/pkg/access/subject-mapping-resolution"
)

type PolicyDecisionPoint interface {
	// Initialize a plugin PDP with a dedicated logger and access to policy
	New(ctx context.Context, l *logger.Logger, store policyStore.EntitlementPolicyStore, attributeFQNPrefixes []string) error
	// Make a decision based on an entity representation, platform policy entitlements, a requested action, and a relevant resource
	GetDecision(ctx context.Context, entity EntityI, action *policy.Action, resource *authzV2.Resource) (bool, error)
	// Determine if a given resource is able to be decisioned upon by this PDP implementation
	IsValidDecisionableResource(resource *authzV2.Resource) bool
	// Determine if a given action is able to be decisioned upon by this PDP implementation
	IsValidDecisionableAction(action *policy.Action) bool
	// Check any dependencies or initialization state for readiness
	IsReady(ctx context.Context) bool
	// Provide the name of the plugin PDP implementation
	Name() string
}

type PolicyDecisionPointConfig struct {
	PolicyDecisionPointI PolicyDecisionPoint
	AttributePrefixes    []string `mapstructure:"resource_fqn_prefixes" json:"resource_fqn_prefixes"`
	Name                 string   `mapstructure:"name" json:"name"`
}

type EntityI interface {
	EntityRepresentation() *ersV2.EntityRepresentation
	Entitlements() *subjectmappingresolution.AttributeValueFQNsToActions
	OriginalEntity() *authzV2.EntityIdentifier
}

type Entity struct {
	entityRepresentation *ersV2.EntityRepresentation
	entitlements         *subjectmappingresolution.AttributeValueFQNsToActions
	originalEntity       *authzV2.EntityIdentifier
}

// TODO: take in only the EntityIdentifier, an SDK, and Policy (attrs/SMs/RegisteredResources)
// then do the work to resolve each of the pieces via an ERS roundtrip and SM resolution
func NewEntity(
	entityRepresentation *ersV2.EntityRepresentation,
	entitlements *subjectmappingresolution.AttributeValueFQNsToActions,
	originalEntity *authzV2.EntityIdentifier,
) *Entity {
	return &Entity{
		entityRepresentation: entityRepresentation,
		entitlements:         entitlements,
		originalEntity:       originalEntity,
	}
}

func (e *Entity) EntityRepresentation() *ersV2.EntityRepresentation {
	return e.entityRepresentation
}

func (e *Entity) Entitlements() *subjectmappingresolution.AttributeValueFQNsToActions {
	return e.entitlements
}

func (e *Entity) OriginalEntity() *authzV2.EntityIdentifier {
	return e.originalEntity
}

// TODO: refactor so we have O(1) lookups by FQN instead of unprocessed lists with O(n) lookup
// type policyStore interface {
// 	AttributeAndValuesByValueFQN()
// 	RegisteredResourceValuesByFQN()
// 	// ObligationValuesByFQN()
// }
