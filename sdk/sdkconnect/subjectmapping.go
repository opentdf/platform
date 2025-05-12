package sdkconnect

import (
	"context"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping/subjectmappingconnect"
	"google.golang.org/grpc"
)

// SubjectMapping Client
type SubjectMappingConnectClient struct {
	subjectmappingconnect.SubjectMappingServiceClient
}

func NewSubjectMappingConnectClient(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) SubjectMappingConnectClient {
	return SubjectMappingConnectClient{
		SubjectMappingServiceClient: subjectmappingconnect.NewSubjectMappingServiceClient(httpClient, baseURL, opts...),
	}
}

func (c SubjectMappingConnectClient) MatchSubjectMappings(ctx context.Context, req *subjectmapping.MatchSubjectMappingsRequest, _ ...grpc.CallOption) (*subjectmapping.MatchSubjectMappingsResponse, error) {
	res, err := c.SubjectMappingServiceClient.MatchSubjectMappings(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c SubjectMappingConnectClient) ListSubjectMappings(ctx context.Context, req *subjectmapping.ListSubjectMappingsRequest, _ ...grpc.CallOption) (*subjectmapping.ListSubjectMappingsResponse, error) {
	res, err := c.SubjectMappingServiceClient.ListSubjectMappings(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c SubjectMappingConnectClient) GetSubjectMapping(ctx context.Context, req *subjectmapping.GetSubjectMappingRequest, _ ...grpc.CallOption) (*subjectmapping.GetSubjectMappingResponse, error) {
	res, err := c.SubjectMappingServiceClient.GetSubjectMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c SubjectMappingConnectClient) CreateSubjectMapping(ctx context.Context, req *subjectmapping.CreateSubjectMappingRequest, _ ...grpc.CallOption) (*subjectmapping.CreateSubjectMappingResponse, error) {
	res, err := c.SubjectMappingServiceClient.CreateSubjectMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c SubjectMappingConnectClient) UpdateSubjectMapping(ctx context.Context, req *subjectmapping.UpdateSubjectMappingRequest, _ ...grpc.CallOption) (*subjectmapping.UpdateSubjectMappingResponse, error) {
	res, err := c.SubjectMappingServiceClient.UpdateSubjectMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c SubjectMappingConnectClient) DeleteSubjectMapping(ctx context.Context, req *subjectmapping.DeleteSubjectMappingRequest, _ ...grpc.CallOption) (*subjectmapping.DeleteSubjectMappingResponse, error) {
	res, err := c.SubjectMappingServiceClient.DeleteSubjectMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c SubjectMappingConnectClient) ListSubjectConditionSets(ctx context.Context, req *subjectmapping.ListSubjectConditionSetsRequest, _ ...grpc.CallOption) (*subjectmapping.ListSubjectConditionSetsResponse, error) {
	res, err := c.SubjectMappingServiceClient.ListSubjectConditionSets(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c SubjectMappingConnectClient) GetSubjectConditionSet(ctx context.Context, req *subjectmapping.GetSubjectConditionSetRequest, _ ...grpc.CallOption) (*subjectmapping.GetSubjectConditionSetResponse, error) {
	res, err := c.SubjectMappingServiceClient.GetSubjectConditionSet(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c SubjectMappingConnectClient) CreateSubjectConditionSet(ctx context.Context, req *subjectmapping.CreateSubjectConditionSetRequest, _ ...grpc.CallOption) (*subjectmapping.CreateSubjectConditionSetResponse, error) {
	res, err := c.SubjectMappingServiceClient.CreateSubjectConditionSet(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c SubjectMappingConnectClient) UpdateSubjectConditionSet(ctx context.Context, req *subjectmapping.UpdateSubjectConditionSetRequest, _ ...grpc.CallOption) (*subjectmapping.UpdateSubjectConditionSetResponse, error) {
	res, err := c.SubjectMappingServiceClient.UpdateSubjectConditionSet(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c SubjectMappingConnectClient) DeleteSubjectConditionSet(ctx context.Context, req *subjectmapping.DeleteSubjectConditionSetRequest, _ ...grpc.CallOption) (*subjectmapping.DeleteSubjectConditionSetResponse, error) {
	res, err := c.SubjectMappingServiceClient.DeleteSubjectConditionSet(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c SubjectMappingConnectClient) DeleteAllUnmappedSubjectConditionSets(ctx context.Context, req *subjectmapping.DeleteAllUnmappedSubjectConditionSetsRequest, _ ...grpc.CallOption) (*subjectmapping.DeleteAllUnmappedSubjectConditionSetsResponse, error) {
	res, err := c.SubjectMappingServiceClient.DeleteAllUnmappedSubjectConditionSets(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
