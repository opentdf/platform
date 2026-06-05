// Wrapper for SubjectMappingServiceClient (generated code) DO NOT EDIT
package sdkconnect

import (
	"connectrpc.com/connect"
	"context"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping/subjectmappingconnect"
)

type SubjectMappingServiceClientConnectWrapper struct {
	subjectmappingconnect.SubjectMappingServiceClient
}

func NewSubjectMappingServiceClientConnectWrapper(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *SubjectMappingServiceClientConnectWrapper {
	return &SubjectMappingServiceClientConnectWrapper{SubjectMappingServiceClient: subjectmappingconnect.NewSubjectMappingServiceClient(httpClient, baseURL, opts...)}
}

type SubjectMappingServiceClient interface {
	MatchSubjectMappings(ctx context.Context, req *subjectmapping.MatchSubjectMappingsRequest) (*subjectmapping.MatchSubjectMappingsResponse, error)
	ListSubjectMappings(ctx context.Context, req *subjectmapping.ListSubjectMappingsRequest) (*subjectmapping.ListSubjectMappingsResponse, error)
	GetSubjectMapping(ctx context.Context, req *subjectmapping.GetSubjectMappingRequest) (*subjectmapping.GetSubjectMappingResponse, error)
	CreateSubjectMapping(ctx context.Context, req *subjectmapping.CreateSubjectMappingRequest) (*subjectmapping.CreateSubjectMappingResponse, error)
	UpdateSubjectMapping(ctx context.Context, req *subjectmapping.UpdateSubjectMappingRequest) (*subjectmapping.UpdateSubjectMappingResponse, error)
	DeleteSubjectMapping(ctx context.Context, req *subjectmapping.DeleteSubjectMappingRequest) (*subjectmapping.DeleteSubjectMappingResponse, error)
	ListSubjectConditionSets(ctx context.Context, req *subjectmapping.ListSubjectConditionSetsRequest) (*subjectmapping.ListSubjectConditionSetsResponse, error)
	GetSubjectConditionSet(ctx context.Context, req *subjectmapping.GetSubjectConditionSetRequest) (*subjectmapping.GetSubjectConditionSetResponse, error)
	CreateSubjectConditionSet(ctx context.Context, req *subjectmapping.CreateSubjectConditionSetRequest) (*subjectmapping.CreateSubjectConditionSetResponse, error)
	UpdateSubjectConditionSet(ctx context.Context, req *subjectmapping.UpdateSubjectConditionSetRequest) (*subjectmapping.UpdateSubjectConditionSetResponse, error)
	DeleteSubjectConditionSet(ctx context.Context, req *subjectmapping.DeleteSubjectConditionSetRequest) (*subjectmapping.DeleteSubjectConditionSetResponse, error)
	DeleteAllUnmappedSubjectConditionSets(ctx context.Context, req *subjectmapping.DeleteAllUnmappedSubjectConditionSetsRequest) (*subjectmapping.DeleteAllUnmappedSubjectConditionSetsResponse, error)
}

func (w *SubjectMappingServiceClientConnectWrapper) MatchSubjectMappings(ctx context.Context, req *subjectmapping.MatchSubjectMappingsRequest) (*subjectmapping.MatchSubjectMappingsResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.SubjectMappingServiceClient.MatchSubjectMappings(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *SubjectMappingServiceClientConnectWrapper) ListSubjectMappings(ctx context.Context, req *subjectmapping.ListSubjectMappingsRequest) (*subjectmapping.ListSubjectMappingsResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.SubjectMappingServiceClient.ListSubjectMappings(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *SubjectMappingServiceClientConnectWrapper) GetSubjectMapping(ctx context.Context, req *subjectmapping.GetSubjectMappingRequest) (*subjectmapping.GetSubjectMappingResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.SubjectMappingServiceClient.GetSubjectMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *SubjectMappingServiceClientConnectWrapper) CreateSubjectMapping(ctx context.Context, req *subjectmapping.CreateSubjectMappingRequest) (*subjectmapping.CreateSubjectMappingResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.SubjectMappingServiceClient.CreateSubjectMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *SubjectMappingServiceClientConnectWrapper) UpdateSubjectMapping(ctx context.Context, req *subjectmapping.UpdateSubjectMappingRequest) (*subjectmapping.UpdateSubjectMappingResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.SubjectMappingServiceClient.UpdateSubjectMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *SubjectMappingServiceClientConnectWrapper) DeleteSubjectMapping(ctx context.Context, req *subjectmapping.DeleteSubjectMappingRequest) (*subjectmapping.DeleteSubjectMappingResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.SubjectMappingServiceClient.DeleteSubjectMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *SubjectMappingServiceClientConnectWrapper) ListSubjectConditionSets(ctx context.Context, req *subjectmapping.ListSubjectConditionSetsRequest) (*subjectmapping.ListSubjectConditionSetsResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.SubjectMappingServiceClient.ListSubjectConditionSets(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *SubjectMappingServiceClientConnectWrapper) GetSubjectConditionSet(ctx context.Context, req *subjectmapping.GetSubjectConditionSetRequest) (*subjectmapping.GetSubjectConditionSetResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.SubjectMappingServiceClient.GetSubjectConditionSet(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *SubjectMappingServiceClientConnectWrapper) CreateSubjectConditionSet(ctx context.Context, req *subjectmapping.CreateSubjectConditionSetRequest) (*subjectmapping.CreateSubjectConditionSetResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.SubjectMappingServiceClient.CreateSubjectConditionSet(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *SubjectMappingServiceClientConnectWrapper) UpdateSubjectConditionSet(ctx context.Context, req *subjectmapping.UpdateSubjectConditionSetRequest) (*subjectmapping.UpdateSubjectConditionSetResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.SubjectMappingServiceClient.UpdateSubjectConditionSet(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *SubjectMappingServiceClientConnectWrapper) DeleteSubjectConditionSet(ctx context.Context, req *subjectmapping.DeleteSubjectConditionSetRequest) (*subjectmapping.DeleteSubjectConditionSetResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.SubjectMappingServiceClient.DeleteSubjectConditionSet(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *SubjectMappingServiceClientConnectWrapper) DeleteAllUnmappedSubjectConditionSets(ctx context.Context, req *subjectmapping.DeleteAllUnmappedSubjectConditionSetsRequest) (*subjectmapping.DeleteAllUnmappedSubjectConditionSetsResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.SubjectMappingServiceClient.DeleteAllUnmappedSubjectConditionSets(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
