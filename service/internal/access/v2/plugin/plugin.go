package plugin

import (
	"context"

	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	ersV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	policy "github.com/opentdf/platform/protocol/go/policy"
	policyStore "github.com/opentdf/platform/service/internal/access/v2/store"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin"
	"github.com/opentdf/platform/service/logger"
)

type PolicyDecisionPoint interface {
	// Initialize a plugin PDP with a dedicated logger and access to policy
	New(ctx context.Context, l *logger.Logger, store policyStore.EntitlementPolicyStore, attributeFQNPrefixes []string) error
	// Make a decision based on an entity representation, platform policy entitlements, a requested action, and a relevant resource
	GetDecision(ctx context.Context, entityRepresentation *ersV2.EntityRepresentation, entitlements *subjectmappingbuiltin.AttributeValueFQNsToActions, action *policy.Action, resource *authzV2.Resource) (bool, error)
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

// TODO: refactor so we have O(1) lookups by FQN instead of unprocessed lists with O(n) lookup
// type policyStore interface {
// 	AttributeAndValuesByValueFQN()
// 	RegisteredResourceValuesByFQN()
// 	// ObligationValuesByFQN()
// }
