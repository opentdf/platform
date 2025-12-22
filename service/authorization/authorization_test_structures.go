package authorization

import (
	"context"
	"fmt"

	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/policy"
	attr "github.com/opentdf/platform/protocol/go/policy/attributes"
	sm "github.com/opentdf/platform/protocol/go/policy/subjectmapping"
)

var (
	getAttributesByValueFqnsResponse attr.GetAttributeValuesByFqnsResponse
	errGetAttributesByValueFqns      error
	listAttributeResp                attr.ListAttributesResponse
	errListAttributes                error
	listSubjectMappings              sm.ListSubjectMappingsResponse
	createEntityChainResp            entityresolution.CreateEntityChainFromJwtResponse
	resolveEntitiesResp              entityresolution.ResolveEntitiesResponse
	mockNamespace                    = "www.example.org"
	mockAttrName                     = "foo"
	mockAttrValue1                   = "value1"
	mockAttrValue2                   = "value2"
	mockAttrValue3                   = "value3"
	mockFqn1                         = fmt.Sprintf("https://%s/attr/%s/value/%s", mockNamespace, mockAttrName, mockAttrValue1)
	mockFqn2                         = fmt.Sprintf("https://%s/attr/%s/value/%s", mockNamespace, mockAttrName, mockAttrValue2)
	mockFqn3                         = fmt.Sprintf("https://%s/attr/%s/value/%s", mockNamespace, mockAttrName, mockAttrValue3)
)

// //// Mock attributes client for testing /////
type myAttributesClient struct{}

func (*myAttributesClient) ListAttributes(_ context.Context, _ *attr.ListAttributesRequest) (*attr.ListAttributesResponse, error) {
	return &listAttributeResp, errListAttributes
}

func (*myAttributesClient) GetAttributeValuesByFqns(_ context.Context, _ *attr.GetAttributeValuesByFqnsRequest) (*attr.GetAttributeValuesByFqnsResponse, error) {
	return &getAttributesByValueFqnsResponse, errGetAttributesByValueFqns
}

func (*myAttributesClient) ListAttributeValues(_ context.Context, _ *attr.ListAttributeValuesRequest) (*attr.ListAttributeValuesResponse, error) {
	return &attr.ListAttributeValuesResponse{}, nil
}

func (*myAttributesClient) GetAttribute(_ context.Context, _ *attr.GetAttributeRequest) (*attr.GetAttributeResponse, error) {
	return &attr.GetAttributeResponse{}, nil
}

func (*myAttributesClient) GetAttributeValue(_ context.Context, _ *attr.GetAttributeValueRequest) (*attr.GetAttributeValueResponse, error) {
	return &attr.GetAttributeValueResponse{}, nil
}

func (*myAttributesClient) CreateAttribute(_ context.Context, _ *attr.CreateAttributeRequest) (*attr.CreateAttributeResponse, error) {
	return &attr.CreateAttributeResponse{}, nil
}

func (*myAttributesClient) UpdateAttribute(_ context.Context, _ *attr.UpdateAttributeRequest) (*attr.UpdateAttributeResponse, error) {
	return &attr.UpdateAttributeResponse{}, nil
}

func (*myAttributesClient) DeactivateAttribute(_ context.Context, _ *attr.DeactivateAttributeRequest) (*attr.DeactivateAttributeResponse, error) {
	return &attr.DeactivateAttributeResponse{}, nil
}

func (*myAttributesClient) CreateAttributeValue(_ context.Context, _ *attr.CreateAttributeValueRequest) (*attr.CreateAttributeValueResponse, error) {
	return &attr.CreateAttributeValueResponse{}, nil
}

func (*myAttributesClient) UpdateAttributeValue(_ context.Context, _ *attr.UpdateAttributeValueRequest) (*attr.UpdateAttributeValueResponse, error) {
	return &attr.UpdateAttributeValueResponse{}, nil
}

func (*myAttributesClient) DeactivateAttributeValue(_ context.Context, _ *attr.DeactivateAttributeValueRequest) (*attr.DeactivateAttributeValueResponse, error) {
	return &attr.DeactivateAttributeValueResponse{}, nil
}

//nolint:staticcheck // SA1019: AssignKeyAccessServerToAttribute is deprecated but required for test mock
func (*myAttributesClient) AssignKeyAccessServerToAttribute(_ context.Context, _ *attr.AssignKeyAccessServerToAttributeRequest) (*attr.AssignKeyAccessServerToAttributeResponse, error) {
	return &attr.AssignKeyAccessServerToAttributeResponse{}, nil
}

//nolint:staticcheck // SA1019: RemoveKeyAccessServerFromAttribute is deprecated but required for test mock
func (*myAttributesClient) RemoveKeyAccessServerFromAttribute(_ context.Context, _ *attr.RemoveKeyAccessServerFromAttributeRequest) (*attr.RemoveKeyAccessServerFromAttributeResponse, error) {
	return &attr.RemoveKeyAccessServerFromAttributeResponse{}, nil
}

//nolint:staticcheck // SA1019: AssignKeyAccessServerToValue is deprecated but required for test mock
func (*myAttributesClient) AssignKeyAccessServerToValue(_ context.Context, _ *attr.AssignKeyAccessServerToValueRequest) (*attr.AssignKeyAccessServerToValueResponse, error) {
	return &attr.AssignKeyAccessServerToValueResponse{}, nil
}

//nolint:staticcheck // SA1019: RemoveKeyAccessServerFromValue is deprecated but required for test mock
func (*myAttributesClient) RemoveKeyAccessServerFromValue(_ context.Context, _ *attr.RemoveKeyAccessServerFromValueRequest) (*attr.RemoveKeyAccessServerFromValueResponse, error) {
	return &attr.RemoveKeyAccessServerFromValueResponse{}, nil
}

func (*myAttributesClient) AssignPublicKeyToAttribute(_ context.Context, _ *attr.AssignPublicKeyToAttributeRequest) (*attr.AssignPublicKeyToAttributeResponse, error) {
	return &attr.AssignPublicKeyToAttributeResponse{}, nil
}

func (*myAttributesClient) RemovePublicKeyFromAttribute(_ context.Context, _ *attr.RemovePublicKeyFromAttributeRequest) (*attr.RemovePublicKeyFromAttributeResponse, error) {
	return &attr.RemovePublicKeyFromAttributeResponse{}, nil
}

func (*myAttributesClient) AssignPublicKeyToValue(_ context.Context, _ *attr.AssignPublicKeyToValueRequest) (*attr.AssignPublicKeyToValueResponse, error) {
	return &attr.AssignPublicKeyToValueResponse{}, nil
}

func (*myAttributesClient) RemovePublicKeyFromValue(_ context.Context, _ *attr.RemovePublicKeyFromValueRequest) (*attr.RemovePublicKeyFromValueResponse, error) {
	return &attr.RemovePublicKeyFromValueResponse{}, nil
}

// // Mock ERS Client for testing /////
type myERSClient struct{}

func (*myERSClient) CreateEntityChainFromJwt(_ context.Context, _ *entityresolution.CreateEntityChainFromJwtRequest) (*entityresolution.CreateEntityChainFromJwtResponse, error) {
	return &createEntityChainResp, nil
}

func (*myERSClient) ResolveEntities(_ context.Context, _ *entityresolution.ResolveEntitiesRequest) (*entityresolution.ResolveEntitiesResponse, error) {
	return &resolveEntitiesResp, nil
}

// // Mock Subject Mapping Client for testing /////
type mySubjectMappingClient struct{}

func (*mySubjectMappingClient) ListSubjectMappings(_ context.Context, _ *sm.ListSubjectMappingsRequest) (*sm.ListSubjectMappingsResponse, error) {
	return &listSubjectMappings, nil
}

func (*mySubjectMappingClient) MatchSubjectMappings(_ context.Context, _ *sm.MatchSubjectMappingsRequest) (*sm.MatchSubjectMappingsResponse, error) {
	return &sm.MatchSubjectMappingsResponse{}, nil
}

func (*mySubjectMappingClient) GetSubjectMapping(_ context.Context, _ *sm.GetSubjectMappingRequest) (*sm.GetSubjectMappingResponse, error) {
	return &sm.GetSubjectMappingResponse{}, nil
}

func (*mySubjectMappingClient) CreateSubjectMapping(_ context.Context, _ *sm.CreateSubjectMappingRequest) (*sm.CreateSubjectMappingResponse, error) {
	return &sm.CreateSubjectMappingResponse{}, nil
}

func (*mySubjectMappingClient) UpdateSubjectMapping(_ context.Context, _ *sm.UpdateSubjectMappingRequest) (*sm.UpdateSubjectMappingResponse, error) {
	return &sm.UpdateSubjectMappingResponse{}, nil
}

func (*mySubjectMappingClient) DeleteSubjectMapping(_ context.Context, _ *sm.DeleteSubjectMappingRequest) (*sm.DeleteSubjectMappingResponse, error) {
	return &sm.DeleteSubjectMappingResponse{}, nil
}

func (*mySubjectMappingClient) ListSubjectConditionSets(_ context.Context, _ *sm.ListSubjectConditionSetsRequest) (*sm.ListSubjectConditionSetsResponse, error) {
	return &sm.ListSubjectConditionSetsResponse{}, nil
}

func (*mySubjectMappingClient) GetSubjectConditionSet(_ context.Context, _ *sm.GetSubjectConditionSetRequest) (*sm.GetSubjectConditionSetResponse, error) {
	return &sm.GetSubjectConditionSetResponse{}, nil
}

func (*mySubjectMappingClient) CreateSubjectConditionSet(_ context.Context, _ *sm.CreateSubjectConditionSetRequest) (*sm.CreateSubjectConditionSetResponse, error) {
	return &sm.CreateSubjectConditionSetResponse{}, nil
}

func (*mySubjectMappingClient) UpdateSubjectConditionSet(_ context.Context, _ *sm.UpdateSubjectConditionSetRequest) (*sm.UpdateSubjectConditionSetResponse, error) {
	return &sm.UpdateSubjectConditionSetResponse{}, nil
}

func (*mySubjectMappingClient) DeleteSubjectConditionSet(_ context.Context, _ *sm.DeleteSubjectConditionSetRequest) (*sm.DeleteSubjectConditionSetResponse, error) {
	return &sm.DeleteSubjectConditionSetResponse{}, nil
}

func (*mySubjectMappingClient) DeleteAllUnmappedSubjectConditionSets(_ context.Context, _ *sm.DeleteAllUnmappedSubjectConditionSetsRequest) (*sm.DeleteAllUnmappedSubjectConditionSetsResponse, error) {
	return &sm.DeleteAllUnmappedSubjectConditionSetsResponse{}, nil
}

// // Mock paginated Subject Mapping Client for testing /////
type paginatedMockSubjectMappingClient struct{}

var (
	smPaginationOffset = 3
	smListCallCount    = 0
)

func (*paginatedMockSubjectMappingClient) ListSubjectMappings(_ context.Context, _ *sm.ListSubjectMappingsRequest) (*sm.ListSubjectMappingsResponse, error) {
	smListCallCount++
	// simulate paginated list and policy LIST behavior
	if smPaginationOffset > 0 {
		rsp := &sm.ListSubjectMappingsResponse{
			SubjectMappings: nil,
			Pagination: &policy.PageResponse{
				NextOffset: int32(smPaginationOffset),
			},
		}
		smPaginationOffset = 0
		return rsp, nil
	}
	return &listSubjectMappings, nil
}

func (*paginatedMockSubjectMappingClient) MatchSubjectMappings(_ context.Context, _ *sm.MatchSubjectMappingsRequest) (*sm.MatchSubjectMappingsResponse, error) {
	return &sm.MatchSubjectMappingsResponse{}, nil
}

func (*paginatedMockSubjectMappingClient) GetSubjectMapping(_ context.Context, _ *sm.GetSubjectMappingRequest) (*sm.GetSubjectMappingResponse, error) {
	return &sm.GetSubjectMappingResponse{}, nil
}

func (*paginatedMockSubjectMappingClient) CreateSubjectMapping(_ context.Context, _ *sm.CreateSubjectMappingRequest) (*sm.CreateSubjectMappingResponse, error) {
	return &sm.CreateSubjectMappingResponse{}, nil
}

func (*paginatedMockSubjectMappingClient) UpdateSubjectMapping(_ context.Context, _ *sm.UpdateSubjectMappingRequest) (*sm.UpdateSubjectMappingResponse, error) {
	return &sm.UpdateSubjectMappingResponse{}, nil
}

func (*paginatedMockSubjectMappingClient) DeleteSubjectMapping(_ context.Context, _ *sm.DeleteSubjectMappingRequest) (*sm.DeleteSubjectMappingResponse, error) {
	return &sm.DeleteSubjectMappingResponse{}, nil
}

func (*paginatedMockSubjectMappingClient) ListSubjectConditionSets(_ context.Context, _ *sm.ListSubjectConditionSetsRequest) (*sm.ListSubjectConditionSetsResponse, error) {
	return &sm.ListSubjectConditionSetsResponse{}, nil
}

func (*paginatedMockSubjectMappingClient) GetSubjectConditionSet(_ context.Context, _ *sm.GetSubjectConditionSetRequest) (*sm.GetSubjectConditionSetResponse, error) {
	return &sm.GetSubjectConditionSetResponse{}, nil
}

func (*paginatedMockSubjectMappingClient) CreateSubjectConditionSet(_ context.Context, _ *sm.CreateSubjectConditionSetRequest) (*sm.CreateSubjectConditionSetResponse, error) {
	return &sm.CreateSubjectConditionSetResponse{}, nil
}

func (*paginatedMockSubjectMappingClient) UpdateSubjectConditionSet(_ context.Context, _ *sm.UpdateSubjectConditionSetRequest) (*sm.UpdateSubjectConditionSetResponse, error) {
	return &sm.UpdateSubjectConditionSetResponse{}, nil
}

func (*paginatedMockSubjectMappingClient) DeleteSubjectConditionSet(_ context.Context, _ *sm.DeleteSubjectConditionSetRequest) (*sm.DeleteSubjectConditionSetResponse, error) {
	return &sm.DeleteSubjectConditionSetResponse{}, nil
}

func (*paginatedMockSubjectMappingClient) DeleteAllUnmappedSubjectConditionSets(_ context.Context, _ *sm.DeleteAllUnmappedSubjectConditionSetsRequest) (*sm.DeleteAllUnmappedSubjectConditionSetsResponse, error) {
	return &sm.DeleteAllUnmappedSubjectConditionSetsResponse{}, nil
}

// // Mock paginated attributs client for testing ////
type paginatedMockAttributesClient struct{}

var (
	attrPaginationOffset = 3
	attrListCallCount    = 0
)

func (*paginatedMockAttributesClient) ListAttributes(_ context.Context, _ *attr.ListAttributesRequest) (*attr.ListAttributesResponse, error) {
	attrListCallCount++
	// simulate paginated list and policy LIST behavior
	if attrPaginationOffset > 0 {
		rsp := &attr.ListAttributesResponse{
			Attributes: nil,
			Pagination: &policy.PageResponse{
				NextOffset: int32(attrPaginationOffset),
			},
		}
		attrPaginationOffset = 0
		return rsp, nil
	}
	return &listAttributeResp, nil
}

func (*paginatedMockAttributesClient) GetAttributeValuesByFqns(_ context.Context, _ *attr.GetAttributeValuesByFqnsRequest) (*attr.GetAttributeValuesByFqnsResponse, error) {
	return &attr.GetAttributeValuesByFqnsResponse{}, nil
}

func (*paginatedMockAttributesClient) ListAttributeValues(_ context.Context, _ *attr.ListAttributeValuesRequest) (*attr.ListAttributeValuesResponse, error) {
	return &attr.ListAttributeValuesResponse{}, nil
}

func (*paginatedMockAttributesClient) GetAttribute(_ context.Context, _ *attr.GetAttributeRequest) (*attr.GetAttributeResponse, error) {
	return &attr.GetAttributeResponse{}, nil
}

func (*paginatedMockAttributesClient) GetAttributeValue(_ context.Context, _ *attr.GetAttributeValueRequest) (*attr.GetAttributeValueResponse, error) {
	return &attr.GetAttributeValueResponse{}, nil
}

func (*paginatedMockAttributesClient) CreateAttribute(_ context.Context, _ *attr.CreateAttributeRequest) (*attr.CreateAttributeResponse, error) {
	return &attr.CreateAttributeResponse{}, nil
}

func (*paginatedMockAttributesClient) UpdateAttribute(_ context.Context, _ *attr.UpdateAttributeRequest) (*attr.UpdateAttributeResponse, error) {
	return &attr.UpdateAttributeResponse{}, nil
}

func (*paginatedMockAttributesClient) DeactivateAttribute(_ context.Context, _ *attr.DeactivateAttributeRequest) (*attr.DeactivateAttributeResponse, error) {
	return &attr.DeactivateAttributeResponse{}, nil
}

func (*paginatedMockAttributesClient) CreateAttributeValue(_ context.Context, _ *attr.CreateAttributeValueRequest) (*attr.CreateAttributeValueResponse, error) {
	return &attr.CreateAttributeValueResponse{}, nil
}

func (*paginatedMockAttributesClient) UpdateAttributeValue(_ context.Context, _ *attr.UpdateAttributeValueRequest) (*attr.UpdateAttributeValueResponse, error) {
	return &attr.UpdateAttributeValueResponse{}, nil
}

func (*paginatedMockAttributesClient) DeactivateAttributeValue(_ context.Context, _ *attr.DeactivateAttributeValueRequest) (*attr.DeactivateAttributeValueResponse, error) {
	return &attr.DeactivateAttributeValueResponse{}, nil
}

//nolint:staticcheck // SA1019: AssignKeyAccessServerToAttribute is deprecated but required for test mock
func (*paginatedMockAttributesClient) AssignKeyAccessServerToAttribute(_ context.Context, _ *attr.AssignKeyAccessServerToAttributeRequest) (*attr.AssignKeyAccessServerToAttributeResponse, error) {
	return &attr.AssignKeyAccessServerToAttributeResponse{}, nil
}

//nolint:staticcheck // SA1019: RemoveKeyAccessServerFromAttribute is deprecated but required for test mock
func (*paginatedMockAttributesClient) RemoveKeyAccessServerFromAttribute(_ context.Context, _ *attr.RemoveKeyAccessServerFromAttributeRequest) (*attr.RemoveKeyAccessServerFromAttributeResponse, error) {
	return &attr.RemoveKeyAccessServerFromAttributeResponse{}, nil
}

//nolint:staticcheck // SA1019: AssignKeyAccessServerToValue is deprecated but required for test mock
func (*paginatedMockAttributesClient) AssignKeyAccessServerToValue(_ context.Context, _ *attr.AssignKeyAccessServerToValueRequest) (*attr.AssignKeyAccessServerToValueResponse, error) {
	return &attr.AssignKeyAccessServerToValueResponse{}, nil
}

//nolint:staticcheck // SA1019: RemoveKeyAccessServerFromValue is deprecated but required for test mock
func (*paginatedMockAttributesClient) RemoveKeyAccessServerFromValue(_ context.Context, _ *attr.RemoveKeyAccessServerFromValueRequest) (*attr.RemoveKeyAccessServerFromValueResponse, error) {
	return &attr.RemoveKeyAccessServerFromValueResponse{}, nil
}

func (*paginatedMockAttributesClient) AssignPublicKeyToAttribute(_ context.Context, _ *attr.AssignPublicKeyToAttributeRequest) (*attr.AssignPublicKeyToAttributeResponse, error) {
	return &attr.AssignPublicKeyToAttributeResponse{}, nil
}

func (*paginatedMockAttributesClient) RemovePublicKeyFromAttribute(_ context.Context, _ *attr.RemovePublicKeyFromAttributeRequest) (*attr.RemovePublicKeyFromAttributeResponse, error) {
	return &attr.RemovePublicKeyFromAttributeResponse{}, nil
}

func (*paginatedMockAttributesClient) AssignPublicKeyToValue(_ context.Context, _ *attr.AssignPublicKeyToValueRequest) (*attr.AssignPublicKeyToValueResponse, error) {
	return &attr.AssignPublicKeyToValueResponse{}, nil
}

func (*paginatedMockAttributesClient) RemovePublicKeyFromValue(_ context.Context, _ *attr.RemovePublicKeyFromValueRequest) (*attr.RemovePublicKeyFromValueResponse, error) {
	return &attr.RemovePublicKeyFromValueResponse{}, nil
}
