// Wrapper for SubjectMappingServiceClient (generated code) DO NOT EDIT
package sdkconnect

import (
	"connectrpc.com/connect"
	"context"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping/subjectmappingconnect"
	"google.golang.org/grpc"
)

type SubjectMappingServiceClientConnectWrapper struct {
	subjectmappingconnect.SubjectMappingServiceClient
}

func NewSubjectMappingServiceClientConnectWrapper(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *SubjectMappingServiceClientConnectWrapper {
	return &SubjectMappingServiceClientConnectWrapper{SubjectMappingServiceClient: subjectmappingconnect.NewSubjectMappingServiceClient(httpClient, baseURL, opts...)}
}

func (w *SubjectMappingServiceClientConnectWrapper) MatchSubjectMappings(ctx context.Context, req *subjectmapping.MatchSubjectMappingsRequest, _ ...grpc.CallOption) (*subjectmapping.MatchSubjectMappingsResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.SubjectMappingServiceClient.MatchSubjectMappings(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *SubjectMappingServiceClientConnectWrapper) ListSubjectMappings(ctx context.Context, req *subjectmapping.ListSubjectMappingsRequest, _ ...grpc.CallOption) (*subjectmapping.ListSubjectMappingsResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.SubjectMappingServiceClient.ListSubjectMappings(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *SubjectMappingServiceClientConnectWrapper) GetSubjectMapping(ctx context.Context, req *subjectmapping.GetSubjectMappingRequest, _ ...grpc.CallOption) (*subjectmapping.GetSubjectMappingResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.SubjectMappingServiceClient.GetSubjectMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *SubjectMappingServiceClientConnectWrapper) CreateSubjectMapping(ctx context.Context, req *subjectmapping.CreateSubjectMappingRequest, _ ...grpc.CallOption) (*subjectmapping.CreateSubjectMappingResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.SubjectMappingServiceClient.CreateSubjectMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *SubjectMappingServiceClientConnectWrapper) UpdateSubjectMapping(ctx context.Context, req *subjectmapping.UpdateSubjectMappingRequest, _ ...grpc.CallOption) (*subjectmapping.UpdateSubjectMappingResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.SubjectMappingServiceClient.UpdateSubjectMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *SubjectMappingServiceClientConnectWrapper) DeleteSubjectMapping(ctx context.Context, req *subjectmapping.DeleteSubjectMappingRequest, _ ...grpc.CallOption) (*subjectmapping.DeleteSubjectMappingResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.SubjectMappingServiceClient.DeleteSubjectMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *SubjectMappingServiceClientConnectWrapper) ListSubjectConditionSets(ctx context.Context, req *subjectmapping.ListSubjectConditionSetsRequest, _ ...grpc.CallOption) (*subjectmapping.ListSubjectConditionSetsResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.SubjectMappingServiceClient.ListSubjectConditionSets(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *SubjectMappingServiceClientConnectWrapper) GetSubjectConditionSet(ctx context.Context, req *subjectmapping.GetSubjectConditionSetRequest, _ ...grpc.CallOption) (*subjectmapping.GetSubjectConditionSetResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.SubjectMappingServiceClient.GetSubjectConditionSet(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *SubjectMappingServiceClientConnectWrapper) CreateSubjectConditionSet(ctx context.Context, req *subjectmapping.CreateSubjectConditionSetRequest, _ ...grpc.CallOption) (*subjectmapping.CreateSubjectConditionSetResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.SubjectMappingServiceClient.CreateSubjectConditionSet(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *SubjectMappingServiceClientConnectWrapper) UpdateSubjectConditionSet(ctx context.Context, req *subjectmapping.UpdateSubjectConditionSetRequest, _ ...grpc.CallOption) (*subjectmapping.UpdateSubjectConditionSetResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.SubjectMappingServiceClient.UpdateSubjectConditionSet(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *SubjectMappingServiceClientConnectWrapper) DeleteSubjectConditionSet(ctx context.Context, req *subjectmapping.DeleteSubjectConditionSetRequest, _ ...grpc.CallOption) (*subjectmapping.DeleteSubjectConditionSetResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.SubjectMappingServiceClient.DeleteSubjectConditionSet(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *SubjectMappingServiceClientConnectWrapper) DeleteAllUnmappedSubjectConditionSets(ctx context.Context, req *subjectmapping.DeleteAllUnmappedSubjectConditionSetsRequest, _ ...grpc.CallOption) (*subjectmapping.DeleteAllUnmappedSubjectConditionSetsResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.SubjectMappingServiceClient.DeleteAllUnmappedSubjectConditionSets(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
