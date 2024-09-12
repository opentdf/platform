package resourcemapping

import (
	"context"
	"log/slog"
	"net/http"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping/resourcemappingconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type ResourceMappingService struct { //nolint:revive // ResourceMappingService is a valid name for this struct
	resourcemapping.UnimplementedResourceMappingServiceServer
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
}

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		ServiceDesc: &resourcemapping.ResourceMappingService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			rs := &ResourceMappingService{dbClient: policydb.NewClient(srp.DBClient, srp.Logger), logger: srp.Logger}
			return rs, func(ctx context.Context, mux *http.ServeMux, s any) {
				path, handler := resourcemappingconnect.NewResourceMappingServiceHandler(rs)
				mux.Handle(path, handler)
			}
		},
	}
}

/*
	Resource Mapping Groups
*/

func (s ResourceMappingService) ListResourceMappingGroups(ctx context.Context, req *connect.Request[resourcemapping.ListResourceMappingGroupsRequest]) (*connect.Response[resourcemapping.ListResourceMappingGroupsResponse], error) {
	r := req.Msg
	rmGroups, err := s.dbClient.ListResourceMappingGroups(ctx, r)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}
	rsp := &resourcemapping.ListResourceMappingGroupsResponse{
		ResourceMappingGroups: rmGroups,
	}
	return &connect.Response[resourcemapping.ListResourceMappingGroupsResponse]{Msg: rsp}, nil
}

func (s ResourceMappingService) GetResourceMappingGroup(ctx context.Context, req *connect.Request[resourcemapping.GetResourceMappingGroupRequest]) (*connect.Response[resourcemapping.GetResourceMappingGroupResponse], error) {
	r := req.Msg
	rmGroup, err := s.dbClient.GetResourceMappingGroup(ctx, r.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", r.GetId()))
	}
	rsp := &resourcemapping.GetResourceMappingGroupResponse{
		ResourceMappingGroup: rmGroup,
	}
	return &connect.Response[resourcemapping.GetResourceMappingGroupResponse]{Msg: rsp}, nil
}

func (s ResourceMappingService) CreateResourceMappingGroup(ctx context.Context, req *connect.Request[resourcemapping.CreateResourceMappingGroupRequest]) (*connect.Response[resourcemapping.CreateResourceMappingGroupResponse], error) {
	r := req.Msg
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeResourceMappingGroup,
	}

	rmGroup, err := s.dbClient.CreateResourceMappingGroup(ctx, r)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("resourceMappingGroup", r.String()))
	}

	auditParams.ObjectID = rmGroup.GetId()
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	rsp := &resourcemapping.CreateResourceMappingGroupResponse{
		ResourceMappingGroup: rmGroup,
	}
	return &connect.Response[resourcemapping.CreateResourceMappingGroupResponse]{Msg: rsp}, nil
}

func (s ResourceMappingService) UpdateResourceMappingGroup(ctx context.Context, req *connect.Request[resourcemapping.UpdateResourceMappingGroupRequest]) (*connect.Response[resourcemapping.UpdateResourceMappingGroupResponse], error) {
	r := req.Msg
	id := r.GetId()

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeResourceMappingGroup,
		ObjectID:   id,
	}

	originalRmGroup, err := s.dbClient.GetResourceMappingGroup(ctx, id)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
	}

	item, err := s.dbClient.UpdateResourceMappingGroup(ctx, id, r)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", id), slog.String("resourceMappingGroup", r.String()))
	}

	// UpdateResourceMappingGroup only returns the ID of the updated resource mapping group
	// so we need to fetch the updated resource mapping to compute the audit diff
	// todo: would be easier to just return the whole group on update
	updatedRmGroup, err := s.dbClient.GetResourceMappingGroup(ctx, id)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
	}

	auditParams.Original = originalRmGroup
	auditParams.Updated = updatedRmGroup
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	rsp := &resourcemapping.UpdateResourceMappingGroupResponse{
		ResourceMappingGroup: item,
	}
	return &connect.Response[resourcemapping.UpdateResourceMappingGroupResponse]{Msg: rsp}, nil
}

func (s ResourceMappingService) DeleteResourceMappingGroup(ctx context.Context, req *connect.Request[resourcemapping.DeleteResourceMappingGroupRequest]) (*connect.Response[resourcemapping.DeleteResourceMappingGroupResponse], error) {
	r := req.Msg
	id := r.GetId()

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeResourceMappingGroup,
		ObjectID:   id,
	}

	rmGroup, err := s.dbClient.DeleteResourceMappingGroup(ctx, id)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", id))
	}

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	rsp := &resourcemapping.DeleteResourceMappingGroupResponse{
		ResourceMappingGroup: rmGroup,
	}
	return &connect.Response[resourcemapping.DeleteResourceMappingGroupResponse]{Msg: rsp}, nil
}

/*
	Resource Mappings
*/

func (s ResourceMappingService) CreateResourceMapping(ctx context.Context,
	req *connect.Request[resourcemapping.CreateResourceMappingRequest],
) (*connect.Response[resourcemapping.CreateResourceMappingResponse], error) {
	r := req.Msg
	s.logger.Debug("creating resource mapping")

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeResourceMapping,
	}

	rm, err := s.dbClient.CreateResourceMapping(ctx, r)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("resourceMapping", r.String()))
	}

	auditParams.ObjectID = rm.GetId()
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	rsp := &resourcemapping.CreateResourceMappingResponse{
		ResourceMapping: rm,
	}
	return &connect.Response[resourcemapping.CreateResourceMappingResponse]{Msg: rsp}, nil
}

func (s ResourceMappingService) ListResourceMappings(ctx context.Context,
	req *connect.Request[resourcemapping.ListResourceMappingsRequest],
) (*connect.Response[resourcemapping.ListResourceMappingsResponse], error) {
	r := req.Msg
	resourceMappings, err := s.dbClient.ListResourceMappings(ctx, r)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}
	rsp := &resourcemapping.ListResourceMappingsResponse{
		ResourceMappings: resourceMappings,
	}
	return &connect.Response[resourcemapping.ListResourceMappingsResponse]{Msg: rsp}, nil
}

func (s ResourceMappingService) ListResourceMappingsByGroupFqns(ctx context.Context, req *connect.Request[resourcemapping.ListResourceMappingsByGroupFqnsRequest]) (*connect.Response[resourcemapping.ListResourceMappingsByGroupFqnsResponse], error) {
	r := req.Msg
	fqns := r.GetFqns()

	fqnRmGroupMap, err := s.dbClient.ListResourceMappingsByGroupFqns(ctx, fqns)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed, slog.Any("fqns", fqns))
	}
	rsp := &resourcemapping.ListResourceMappingsByGroupFqnsResponse{
		FqnResourceMappingGroups: fqnRmGroupMap,
	}
	return &connect.Response[resourcemapping.ListResourceMappingsByGroupFqnsResponse]{Msg: rsp}, nil
}

func (s ResourceMappingService) GetResourceMapping(ctx context.Context,
	req *connect.Request[resourcemapping.GetResourceMappingRequest],
) (*connect.Response[resourcemapping.GetResourceMappingResponse], error) {
	r := req.Msg
	rm, err := s.dbClient.GetResourceMapping(ctx, r.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", r.GetId()))
	}
	rsp := &resourcemapping.GetResourceMappingResponse{
		ResourceMapping: rm,
	}
	return &connect.Response[resourcemapping.GetResourceMappingResponse]{Msg: rsp}, nil
}

func (s ResourceMappingService) UpdateResourceMapping(ctx context.Context,
	req *connect.Request[resourcemapping.UpdateResourceMappingRequest],
) (*connect.Response[resourcemapping.UpdateResourceMappingResponse], error) {
	r := req.Msg
	resourceMappingID := r.GetId()

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeResourceMapping,
		ObjectID:   resourceMappingID,
	}

	originalRM, err := s.dbClient.GetResourceMapping(ctx, resourceMappingID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	item, err := s.dbClient.UpdateResourceMapping(
		ctx,
		resourceMappingID,
		r,
	)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", r.GetId()), slog.String("resourceMapping", r.String()))
	}

	// UpdateResourceMapping only returns the ID of the updated resource mapping
	// so we need to fetch the updated resource mapping to compute the audit diff
	updatedRM, err := s.dbClient.GetResourceMapping(ctx, resourceMappingID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	auditParams.Original = originalRM
	auditParams.Updated = updatedRM
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	rsp := &resourcemapping.UpdateResourceMappingResponse{
		ResourceMapping: item,
	}
	return &connect.Response[resourcemapping.UpdateResourceMappingResponse]{Msg: rsp}, nil
}

func (s ResourceMappingService) DeleteResourceMapping(ctx context.Context,
	req *connect.Request[resourcemapping.DeleteResourceMappingRequest],
) (*connect.Response[resourcemapping.DeleteResourceMappingResponse], error) {
	r := req.Msg
	resourceMappingID := r.GetId()

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeResourceMapping,
		ObjectID:   resourceMappingID,
	}

	rm, err := s.dbClient.DeleteResourceMapping(ctx, resourceMappingID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", resourceMappingID))
	}
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	rsp := &resourcemapping.DeleteResourceMappingResponse{
		ResourceMapping: rm,
	}
	return &connect.Response[resourcemapping.DeleteResourceMappingResponse]{Msg: rsp}, nil
}
