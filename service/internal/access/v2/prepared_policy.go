package access

import (
	"context"
	"fmt"

	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/internal/access/v2/obligations"
	"github.com/opentdf/platform/service/logger"
)

// PolicyOptions controls how a policy snapshot is compiled.
type PolicyOptions struct {
	AllowDirectEntitlements   bool
	AllowDynamicValueMappings bool
	NamespacedPolicy          bool
}

// PreparedPolicy is immutable after construction and can be shared by requests.
type PreparedPolicy struct {
	options                       PolicyOptions
	registeredResources           []*policy.RegisteredResource
	registeredResourceValuesByFQN map[string]*policy.RegisteredResourceValue
	dynamicValueMappings          []*policy.DynamicValueMapping
	obligationsPDP                *obligations.ObligationsPolicyDecisionPoint
	fullPolicyPDP                 *PolicyDecisionPoint
}

// PreparedPolicyStore optionally supplies already compiled policy to the JIT PDP.
type PreparedPolicyStore interface {
	PreparedPolicy(context.Context) (*PreparedPolicy, error)
}

// NewPreparedPolicy validates and indexes the policy that does not depend on a request.
func NewPreparedPolicy(ctx context.Context, log *logger.Logger, store EntitlementPolicyStore, options PolicyOptions) (*PreparedPolicy, error) {
	prepared := &PreparedPolicy{options: options}
	// Attributes and subject mappings are fetched per request (targeted), so they are no longer
	// loaded here. Registered resources, obligations, and (gated) dynamic value mappings remain
	// fully loaded because they are not covered by GetEntitleableAttributesByFqns.
	allRegisteredResources, err := store.ListAllRegisteredResources(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch all registered resources: %w", err)
	}
	allObligations, err := store.ListAllObligations(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch all obligations: %w", err)
	}
	// Experimental: only load dynamic value mappings when the feature is enabled.
	if options.AllowDynamicValueMappings {
		prepared.dynamicValueMappings, err = store.ListAllDynamicValueMappings(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch all dynamic value mappings: %w", err)
		}
	}
	prepared.registeredResources = allRegisteredResources

	registeredResourceValuesByFQN, err := buildRegisteredResourceValuesByFQN(allRegisteredResources, options.NamespacedPolicy)
	if err != nil {
		return nil, fmt.Errorf("failed to index registered resources: %w", err)
	}
	prepared.registeredResourceValuesByFQN = registeredResourceValuesByFQN

	// Obligations are triggered by (action, attribute value FQN, PEP client) against a trigger graph
	// built from all obligations; the attributes-by-value map is unused by the obligations PDP, so an
	// empty map is passed.
	obligationsPDP, err := obligations.NewObligationsPolicyDecisionPoint(
		ctx,
		log,
		make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue),
		registeredResourceValuesByFQN,
		allObligations,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create new obligations policy decision point: %w", err)
	}
	prepared.obligationsPDP = obligationsPDP

	// Direct entitlements and dynamic value mappings entitle attribute values that may not exist in
	// policy; synthesizing them requires the full definition set, which targeted
	// GetEntitleableAttributesByFqns lookups cannot supply (a non-existent value FQN errors). When
	// either experimental feature is enabled, build the PDP from the full policy load instead.
	if options.AllowDirectEntitlements || options.AllowDynamicValueMappings {
		// Read attributes and subject mappings from the same store used above (the refresh cache when
		// ready, otherwise the live retriever), so a cache-enabled deployment does not re-scan both
		// policy endpoints on every request.
		allAttributes, err := store.ListAllAttributes(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list attributes: %w", err)
		}
		allSubjectMappings, err := store.ListAllSubjectMappings(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list subject mappings: %w", err)
		}
		fullPolicyPDP, err := NewPolicyDecisionPoint(
			ctx,
			log,
			allAttributes,
			allSubjectMappings,
			allRegisteredResources,
			options.AllowDirectEntitlements,
			options.NamespacedPolicy,
			WithDynamicValueMappings(prepared.dynamicValueMappings, options.AllowDynamicValueMappings),
			withRegisteredResourceValues(registeredResourceValuesByFQN),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create full-policy decision point: %w", err)
		}
		prepared.fullPolicyPDP = fullPolicyPDP
	}

	return prepared, nil
}
