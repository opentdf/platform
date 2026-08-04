package access

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/dynamicvaluemapping"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	otdfSDK "github.com/opentdf/platform/sdk"
)

// Shared interface for a cache or the connected retriever below to implement to provide entitlement policy data.
type EntitlementPolicyStore interface {
	ListAllAttributes(ctx context.Context) ([]*policy.Attribute, error)
	ListAllSubjectMappings(ctx context.Context) ([]*policy.SubjectMapping, error)
	ListAllDynamicValueMappings(ctx context.Context) ([]*policy.DynamicValueMapping, error)
	ListAllRegisteredResources(ctx context.Context) ([]*policy.RegisteredResource, error)
	ListAllObligations(ctx context.Context) ([]*policy.Obligation, error)
	IsEnabled() bool
	IsReady(context.Context) bool
}

var (
	ErrFailedToFetchAttributes           = errors.New("failed to fetch attributes from policy service")
	ErrFailedToFetchSubjectMappings      = errors.New("failed to fetch subject mappings from policy service")
	ErrFailedToFetchDynamicValueMappings = errors.New("failed to fetch dynamic value mappings from policy service")
	ErrFailedToFetchRegisteredResources  = errors.New("failed to fetch registered resources from policy service")
	ErrFailedToFetchObligations          = errors.New("failed to fetch obligations from policy service")
)

const (
	// entitlementPolicyMaxPageSize is the optimistic initial page size (matches the policy
	// service's max); paginateAll shrinks it toward the floor on resource_exhausted.
	entitlementPolicyMaxPageSize = 2500
	// entitlementPolicyMinPageSize is the shrink floor; a single object always fits under the limit.
	entitlementPolicyMinPageSize = 1
	// entitlementPolicyPageShrinkDivisor halves the page size on each resource_exhausted retry.
	entitlementPolicyPageShrinkDivisor = 2
)

// isResourceExhausted reports whether err is a connect resource_exhausted error (e.g. a page whose
// serialized size exceeds the max message size, default 4MB).
func isResourceExhausted(err error) bool {
	return connect.CodeOf(err) == connect.CodeResourceExhausted
}

// paginateAll invokes fetchPage until no pages remain (nextOffset <= 0). On resource_exhausted it
// halves the page size and retries the same offset, keeping the load under the message limit
// regardless of object size. fetchPage makes the list request and appends items; it must not append
// when returning an error.
func paginateAll(fetchPage func(offset, limit int32) (nextOffset int32, err error)) error {
	var offset int32
	limit := int32(entitlementPolicyMaxPageSize)
	for {
		nextOffset, err := fetchPage(offset, limit)
		if err != nil {
			if isResourceExhausted(err) && limit > entitlementPolicyMinPageSize {
				limit = max(limit/entitlementPolicyPageShrinkDivisor, entitlementPolicyMinPageSize)
				continue
			}
			return err
		}
		if nextOffset <= 0 {
			return nil
		}
		offset = nextOffset
	}
}

// EntitlementPolicyRetriever satisfies the EntitlementPolicyStore interface and fetches fresh
// entitlement policy data from the policy services via SDK.
type EntitlementPolicyRetriever struct {
	SDK *otdfSDK.SDK
}

func NewEntitlementPolicyRetriever(sdk *otdfSDK.SDK) *EntitlementPolicyRetriever {
	return &EntitlementPolicyRetriever{
		SDK: sdk,
	}
}

func (p *EntitlementPolicyRetriever) IsEnabled() bool {
	return p.SDK != nil
}

func (p *EntitlementPolicyRetriever) IsReady(_ context.Context) bool {
	return p.IsEnabled()
}

func (p *EntitlementPolicyRetriever) ListAllAttributes(ctx context.Context) ([]*policy.Attribute, error) {
	// If quantity of attributes exceeds maximum list pagination, all are needed to determine entitlements
	attrsList := make([]*policy.Attribute, 0)

	err := paginateAll(func(offset, limit int32) (int32, error) {
		listed, err := p.SDK.Attributes.ListAttributes(ctx, &attrs.ListAttributesRequest{
			State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE,
			Pagination: &policy.PageRequest{
				Offset: offset,
				Limit:  limit,
			},
		})
		if err != nil {
			return 0, err
		}
		attrsList = append(attrsList, listed.GetAttributes()...)
		return listed.GetPagination().GetNextOffset(), nil
	})
	if err != nil {
		return nil, errors.Join(ErrFailedToFetchAttributes, err)
	}
	return attrsList, nil
}

func (p *EntitlementPolicyRetriever) ListAllSubjectMappings(ctx context.Context) ([]*policy.SubjectMapping, error) {
	// If quantity of subject mappings exceeds maximum list pagination, all are needed to determine entitlements
	smList := make([]*policy.SubjectMapping, 0)

	err := paginateAll(func(offset, limit int32) (int32, error) {
		listed, err := p.SDK.SubjectMapping.ListSubjectMappings(ctx, &subjectmapping.ListSubjectMappingsRequest{
			Pagination: &policy.PageRequest{
				Offset: offset,
				Limit:  limit,
			},
		})
		if err != nil {
			return 0, err
		}
		smList = append(smList, listed.GetSubjectMappings()...)
		return listed.GetPagination().GetNextOffset(), nil
	})
	if err != nil {
		return nil, errors.Join(ErrFailedToFetchSubjectMappings, err)
	}
	return smList, nil
}

func (p *EntitlementPolicyRetriever) ListAllDynamicValueMappings(ctx context.Context) ([]*policy.DynamicValueMapping, error) {
	// If quantity exceeds maximum list pagination, all are needed to determine entitlements
	mappingsList := make([]*policy.DynamicValueMapping, 0)

	err := paginateAll(func(offset, limit int32) (int32, error) {
		listed, err := p.SDK.DynamicValueMapping.ListDynamicValueMappings(ctx, &dynamicvaluemapping.ListDynamicValueMappingsRequest{
			Pagination: &policy.PageRequest{
				Offset: offset,
				Limit:  limit,
			},
		})
		if err != nil {
			return 0, err
		}
		mappingsList = append(mappingsList, listed.GetDynamicValueMappings()...)
		return listed.GetPagination().GetNextOffset(), nil
	})
	if err != nil {
		return nil, errors.Join(ErrFailedToFetchDynamicValueMappings, err)
	}
	return mappingsList, nil
}

func (p *EntitlementPolicyRetriever) ListAllRegisteredResources(ctx context.Context) ([]*policy.RegisteredResource, error) {
	// If quantity of registered resources exceeds maximum list pagination, all are needed to determine entitlements
	rrList := make([]*policy.RegisteredResource, 0)

	err := paginateAll(func(offset, limit int32) (int32, error) {
		listed, err := p.SDK.RegisteredResources.ListRegisteredResources(ctx, &registeredresources.ListRegisteredResourcesRequest{
			Pagination: &policy.PageRequest{
				Offset: offset,
				Limit:  limit,
			},
		})
		if err != nil {
			return 0, err
		}
		rrList = append(rrList, listed.GetResources()...)
		return listed.GetPagination().GetNextOffset(), nil
	})
	if err != nil {
		return nil, errors.Join(ErrFailedToFetchRegisteredResources, err)
	}
	return rrList, nil
}

func (p *EntitlementPolicyRetriever) ListAllObligations(ctx context.Context) ([]*policy.Obligation, error) {
	// If quantity of obligations exceeds maximum list pagination, all are needed to determine entitlements
	obligationList := make([]*policy.Obligation, 0)

	err := paginateAll(func(offset, limit int32) (int32, error) {
		listed, err := p.SDK.Obligations.ListObligations(ctx, &obligations.ListObligationsRequest{
			Pagination: &policy.PageRequest{
				Offset: offset,
				Limit:  limit,
			},
		})
		if err != nil {
			return 0, err
		}
		obligationList = append(obligationList, listed.GetObligations()...)
		return listed.GetPagination().GetNextOffset(), nil
	})
	if err != nil {
		return nil, errors.Join(ErrFailedToFetchObligations, err)
	}
	return obligationList, nil
}
