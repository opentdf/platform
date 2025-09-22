package access

import (
	"context"
	"errors"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	otdfSDK "github.com/opentdf/platform/sdk"
)

// Shared interface for a cache or the connected retriever below to implement to provide entitlement policy data.
type EntitlementPolicyStore interface {
	ListAllAttributes(ctx context.Context) ([]*policy.Attribute, error)
	ListAllSubjectMappings(ctx context.Context) ([]*policy.SubjectMapping, error)
	ListAllRegisteredResources(ctx context.Context) ([]*policy.RegisteredResource, error)
	ListAllObligations(ctx context.Context) ([]*policy.Obligation, error)
	IsEnabled() bool
	IsReady(context.Context) bool
}

var (
	ErrFailedToFetchAttributes          = errors.New("failed to fetch attributes from policy service")
	ErrFailedToFetchSubjectMappings     = errors.New("failed to fetch subject mappings from policy service")
	ErrFailedToFetchRegisteredResources = errors.New("failed to fetch registered resources from policy service")
	ErrFailedToFetchObligations         = errors.New("failed to fetch obligations from policy service")
)

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
	var nextOffset int32
	attrsList := make([]*policy.Attribute, 0)

	for {
		listed, err := p.SDK.Attributes.ListAttributes(ctx, &attrs.ListAttributesRequest{
			State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE,
			// defer to service default for limit pagination
			Pagination: &policy.PageRequest{
				Offset: nextOffset,
			},
		})
		if err != nil {
			return nil, errors.Join(ErrFailedToFetchAttributes, err)
		}

		nextOffset = listed.GetPagination().GetNextOffset()
		attrsList = append(attrsList, listed.GetAttributes()...)

		if nextOffset <= 0 {
			break
		}
	}
	return attrsList, nil
}

func (p *EntitlementPolicyRetriever) ListAllSubjectMappings(ctx context.Context) ([]*policy.SubjectMapping, error) {
	// If quantity of attributes exceeds maximum list pagination, all are needed to determine entitlements
	var nextOffset int32
	smList := make([]*policy.SubjectMapping, 0)

	for {
		listed, err := p.SDK.SubjectMapping.ListSubjectMappings(ctx, &subjectmapping.ListSubjectMappingsRequest{
			// defer to service default for limit pagination
			Pagination: &policy.PageRequest{
				Offset: nextOffset,
			},
		})
		if err != nil {
			return nil, errors.Join(ErrFailedToFetchSubjectMappings, err)
		}

		nextOffset = listed.GetPagination().GetNextOffset()
		smList = append(smList, listed.GetSubjectMappings()...)

		if nextOffset <= 0 {
			break
		}
	}
	return smList, nil
}

func (p *EntitlementPolicyRetriever) ListAllRegisteredResources(ctx context.Context) ([]*policy.RegisteredResource, error) {
	// If quantity of registered resources exceeds maximum list pagination, all are needed to determine entitlements
	var nextOffset int32
	rrList := make([]*policy.RegisteredResource, 0)

	for {
		listed, err := p.SDK.RegisteredResources.ListRegisteredResources(ctx, &registeredresources.ListRegisteredResourcesRequest{
			// defer to service default for limit pagination
			Pagination: &policy.PageRequest{
				Offset: nextOffset,
			},
		})
		if err != nil {
			return nil, errors.Join(ErrFailedToFetchRegisteredResources, err)
		}

		nextOffset = listed.GetPagination().GetNextOffset()
		rrList = append(rrList, listed.GetResources()...)

		if nextOffset <= 0 {
			break
		}
	}

	return rrList, nil
}

func (p *EntitlementPolicyRetriever) ListAllObligations(ctx context.Context) ([]*policy.Obligation, error) {
	// If quantity of obligationss exceeds maximum list pagination, all are needed to determine entitlements
	var nextOffset int32
	obligationList := make([]*policy.Obligation, 0)

	for {
		listed, err := p.SDK.Obligations.ListObligations(ctx, &obligations.ListObligationsRequest{
			// defer to service default for limit pagination
			Pagination: &policy.PageRequest{
				Offset: nextOffset,
			},
		})
		if err != nil {
			return nil, errors.Join(ErrFailedToFetchObligations, err)
		}

		nextOffset := listed.GetPagination().GetNextOffset()
		obligationList = append(obligationList, listed.GetObligations()...)

		if nextOffset <= 0 {
			break
		}
	}

	return obligationList, nil
}
