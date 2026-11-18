package access

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	otdfSDK "github.com/opentdf/platform/sdk"
)

// maxTriggerValueFQNsPerRequest mirrors the proto max_items limit on
// ListObligationTriggersRequest.attribute_value_fqns.
const maxTriggerValueFQNsPerRequest = 250

// fetchRegisteredResources looks up only the registered resource values named by fqns and groups
// them under their registered resources, in the shape buildRegisteredResourceValuesByFQN and
// NewPolicyDecisionPoint consume.
//
// Unknown or malformed FQNs are omitted rather than treated as errors, matching a fully loaded
// policy: the decision path denies per resource on unknown registered resource values and errors
// when the entity itself is unknown.
func fetchRegisteredResources(ctx context.Context, sdk *otdfSDK.SDK, fqns []string) ([]*policy.RegisteredResource, error) {
	resources := make([]*policy.RegisteredResource, 0)
	resourcesByID := make(map[string]*policy.RegisteredResource)
	// Legacy and namespaced FQNs can resolve to the same value.
	seenValueIDs := make(map[string]struct{})

	for _, fqn := range normalizeFQNs(fqns) {
		rsp, err := sdk.RegisteredResources.GetRegisteredResourceValue(ctx, &registeredresources.GetRegisteredResourceValueRequest{
			Identifier: &registeredresources.GetRegisteredResourceValueRequest_Fqn{Fqn: fqn},
		})
		if err != nil {
			if code := connect.CodeOf(err); code == connect.CodeNotFound || code == connect.CodeInvalidArgument {
				continue
			}
			return nil, errors.Join(ErrFailedToFetchRegisteredResources, err)
		}

		value := rsp.GetValue()
		if _, ok := seenValueIDs[value.GetId()]; ok {
			continue
		}
		seenValueIDs[value.GetId()] = struct{}{}

		parent := value.GetResource()
		resource, ok := resourcesByID[parent.GetId()]
		if !ok {
			resource = &policy.RegisteredResource{
				Id:        parent.GetId(),
				Name:      parent.GetName(),
				Namespace: parent.GetNamespace(),
			}
			resourcesByID[parent.GetId()] = resource
			resources = append(resources, resource)
		}
		resource.Values = append(resource.Values, value)
	}
	return resources, nil
}

// fetchObligationsForValues looks up only the obligation triggers on the provided attribute value
// FQNs and returns them in the []*policy.Obligation shape the obligations PDP consumes. Each
// trigger is wrapped in its own obligation value; the PDP indexes triggers individually, so the
// grouping does not affect which obligations are triggered.
func fetchObligationsForValues(ctx context.Context, sdk *otdfSDK.SDK, valueFQNs []string) ([]*policy.Obligation, error) {
	fqns := normalizeFQNs(valueFQNs)
	obligationList := make([]*policy.Obligation, 0)

	for start := 0; start < len(fqns); start += maxTriggerValueFQNsPerRequest {
		batch := fqns[start:min(start+maxTriggerValueFQNsPerRequest, len(fqns))]

		var nextOffset int32
		for {
			listed, err := sdk.Obligations.ListObligationTriggers(ctx, &obligations.ListObligationTriggersRequest{
				AttributeValueFqns: batch,
				// defer to service default for limit pagination
				Pagination: &policy.PageRequest{
					Offset: nextOffset,
				},
			})
			if err != nil {
				return nil, errors.Join(ErrFailedToFetchObligations, err)
			}

			for _, trigger := range listed.GetTriggers() {
				obligationValue := trigger.GetObligationValue()
				obligationList = append(obligationList, &policy.Obligation{
					Values: []*policy.ObligationValue{{
						Id:       obligationValue.GetId(),
						Value:    obligationValue.GetValue(),
						Fqn:      obligationValue.GetFqn(),
						Triggers: []*policy.ObligationTrigger{trigger},
					}},
				})
			}

			nextOffset = listed.GetPagination().GetNextOffset()
			if nextOffset <= 0 {
				break
			}
		}
	}
	return obligationList, nil
}

// normalizeFQNs lower-cases and dedupes FQNs, dropping empty ones.
func normalizeFQNs(fqns []string) []string {
	normalized := make([]string, 0, len(fqns))
	seen := make(map[string]struct{}, len(fqns))
	for _, fqn := range fqns {
		fqn = strings.ToLower(fqn)
		if fqn == "" {
			continue
		}
		if _, ok := seen[fqn]; ok {
			continue
		}
		seen[fqn] = struct{}{}
		normalized = append(normalized, fqn)
	}
	return normalized
}
