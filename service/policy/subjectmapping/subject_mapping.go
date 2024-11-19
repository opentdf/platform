package subjectmapping

import (
	"context"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy"
	sm "github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping/subjectmappingconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type SubjectMappingService struct { //nolint:revive // SubjectMappingService is a valid name for this struct
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
	config   *policyconfig.Config
}

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[subjectmappingconnect.SubjectMappingServiceHandler] {
	return &serviceregistry.Service[subjectmappingconnect.SubjectMappingServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[subjectmappingconnect.SubjectMappingServiceHandler]{
			Namespace:      ns,
			DB:             dbRegister,
			ServiceDesc:    &sm.SubjectMappingService_ServiceDesc,
			ConnectRPCFunc: subjectmappingconnect.NewSubjectMappingServiceHandler,
			GRPCGateayFunc: sm.RegisterSubjectMappingServiceHandlerFromEndpoint,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (subjectmappingconnect.SubjectMappingServiceHandler, serviceregistry.HandlerServer) {
				cfg := policyconfig.GetSharedPolicyConfig(srp)
				return &SubjectMappingService{
					dbClient: policydb.NewClient(srp.DBClient, srp.Logger, int32(cfg.ListRequestLimitMax), int32(cfg.ListRequestLimitDefault)),
					logger:   srp.Logger,
					config:   cfg,
				}, nil
			},
		},
	}
}

/* ---------------------------------------------------
 * ----------------- SubjectMappings -----------------
 * --------------------------------------------------*/

func (s SubjectMappingService) CreateSubjectMapping(ctx context.Context,
	req *connect.Request[sm.CreateSubjectMappingRequest],
) (*connect.Response[sm.CreateSubjectMappingResponse], error) {
	rsp := &sm.CreateSubjectMappingResponse{}
	s.logger.Debug("creating subject mapping")

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeSubjectMapping,
	}

	subjectMapping, err := s.dbClient.CreateSubjectMapping(ctx, req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("subjectMapping", req.Msg.String()))
	}

	auditParams.ObjectID = subjectMapping.GetId()
	auditParams.Original = subjectMapping
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.SubjectMapping = subjectMapping
	return connect.NewResponse(rsp), nil
}

func (s SubjectMappingService) ListSubjectMappings(ctx context.Context,
	req *connect.Request[sm.ListSubjectMappingsRequest],
) (*connect.Response[sm.ListSubjectMappingsResponse], error) {
	s.logger.Debug("listing subject mappings")

	rsp, err := s.dbClient.ListSubjectMappings(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	return connect.NewResponse(rsp), nil
}

func (s SubjectMappingService) GetSubjectMapping(ctx context.Context,
	req *connect.Request[sm.GetSubjectMappingRequest],
) (*connect.Response[sm.GetSubjectMappingResponse], error) {
	rsp := &sm.GetSubjectMappingResponse{}
	s.logger.Debug("getting subject mapping", slog.String("id", req.Msg.GetId()))

	mapping, err := s.dbClient.GetSubjectMapping(ctx, req.Msg.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.Msg.GetId()))
	}

	rsp.SubjectMapping = mapping
	return connect.NewResponse(rsp), nil
}

func (s SubjectMappingService) UpdateSubjectMapping(ctx context.Context,
	req *connect.Request[sm.UpdateSubjectMappingRequest],
) (*connect.Response[sm.UpdateSubjectMappingResponse], error) {
	rsp := &sm.UpdateSubjectMappingResponse{}
	subjectMappingID := req.Msg.GetId()

	s.logger.Debug("updating subject mapping", slog.String("subjectMapping", req.Msg.String()))

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeSubjectMapping,
		ObjectID:   subjectMappingID,
	}

	original, err := s.dbClient.GetSubjectMapping(ctx, subjectMappingID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", subjectMappingID))
	}

	updated, err := s.dbClient.UpdateSubjectMapping(ctx, req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.Msg.GetId()), slog.String("subjectMapping fields", req.Msg.String()))
	}

	auditParams.Original = original
	auditParams.Updated = updated
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.SubjectMapping = &policy.SubjectMapping{
		Id: subjectMappingID,
	}
	return connect.NewResponse(rsp), nil
}

func (s SubjectMappingService) DeleteSubjectMapping(ctx context.Context,
	req *connect.Request[sm.DeleteSubjectMappingRequest],
) (*connect.Response[sm.DeleteSubjectMappingResponse], error) {
	rsp := &sm.DeleteSubjectMappingResponse{}
	s.logger.Debug("deleting subject mapping", slog.String("id", req.Msg.GetId()))

	subjectMappingID := req.Msg.GetId()
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeSubjectMapping,
		ObjectID:   subjectMappingID,
	}

	_, err := s.dbClient.DeleteSubjectMapping(ctx, subjectMappingID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", subjectMappingID))
	}

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.SubjectMapping = &policy.SubjectMapping{
		Id: subjectMappingID,
	}
	return connect.NewResponse(rsp), nil
}

func (s SubjectMappingService) MatchSubjectMappings(ctx context.Context,
	req *connect.Request[sm.MatchSubjectMappingsRequest],
) (*connect.Response[sm.MatchSubjectMappingsResponse], error) {
	rsp := &sm.MatchSubjectMappingsResponse{}
	s.logger.Debug("matching subject mappings", slog.Any("subjectProperties", req.Msg.GetSubjectProperties()))

	smList, err := s.dbClient.GetMatchedSubjectMappings(ctx, req.Msg.GetSubjectProperties())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.Any("subjectProperties", req.Msg.GetSubjectProperties()))
	}

	rsp.SubjectMappings = smList
	return connect.NewResponse(rsp), nil
}

/* --------------------------------------------------------
 * ----------------- SubjectConditionSets -----------------
 * -------------------------------------------------------*/

func (s SubjectMappingService) GetSubjectConditionSet(ctx context.Context,
	req *connect.Request[sm.GetSubjectConditionSetRequest],
) (*connect.Response[sm.GetSubjectConditionSetResponse], error) {
	rsp := &sm.GetSubjectConditionSetResponse{}
	s.logger.Debug("getting subject condition set", slog.String("id", req.Msg.GetId()))

	conditionSet, err := s.dbClient.GetSubjectConditionSet(ctx, req.Msg.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.Msg.GetId()))
	}

	rsp.SubjectConditionSet = conditionSet
	return connect.NewResponse(rsp), nil
}

func (s SubjectMappingService) ListSubjectConditionSets(ctx context.Context,
	req *connect.Request[sm.ListSubjectConditionSetsRequest],
) (*connect.Response[sm.ListSubjectConditionSetsResponse], error) {
	s.logger.Debug("listing subject condition sets")

	rsp, err := s.dbClient.ListSubjectConditionSets(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	return connect.NewResponse(rsp), nil
}

func (s SubjectMappingService) CreateSubjectConditionSet(ctx context.Context,
	req *connect.Request[sm.CreateSubjectConditionSetRequest],
) (*connect.Response[sm.CreateSubjectConditionSetResponse], error) {
	rsp := &sm.CreateSubjectConditionSetResponse{}
	s.logger.Debug("creating subject condition set", slog.String("subjectConditionSet", req.Msg.String()))

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeConditionSet,
	}

	conditionSet, err := s.dbClient.CreateSubjectConditionSet(ctx, req.Msg.GetSubjectConditionSet())
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("subjectConditionSet", req.Msg.String()))
	}

	auditParams.ObjectID = conditionSet.GetId()
	auditParams.Original = conditionSet
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.SubjectConditionSet = conditionSet
	return connect.NewResponse(rsp), nil
}

func (s SubjectMappingService) UpdateSubjectConditionSet(ctx context.Context,
	req *connect.Request[sm.UpdateSubjectConditionSetRequest],
) (*connect.Response[sm.UpdateSubjectConditionSetResponse], error) {
	rsp := &sm.UpdateSubjectConditionSetResponse{}
	s.logger.Debug("updating subject condition set", slog.String("subjectConditionSet", req.Msg.String()))

	subjectConditionSetID := req.Msg.GetId()
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeConditionSet,
		ObjectID:   subjectConditionSetID,
	}

	original, err := s.dbClient.GetSubjectConditionSet(ctx, subjectConditionSetID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", subjectConditionSetID))
	}

	updated, err := s.dbClient.UpdateSubjectConditionSet(ctx, req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.Msg.GetId()), slog.String("subjectConditionSet fields", req.Msg.String()))
	}

	auditParams.Original = original
	auditParams.Updated = updated
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.SubjectConditionSet = &policy.SubjectConditionSet{
		Id: subjectConditionSetID,
	}
	return connect.NewResponse(rsp), nil
}

func (s SubjectMappingService) DeleteSubjectConditionSet(ctx context.Context,
	req *connect.Request[sm.DeleteSubjectConditionSetRequest],
) (*connect.Response[sm.DeleteSubjectConditionSetResponse], error) {
	rsp := &sm.DeleteSubjectConditionSetResponse{}
	s.logger.Debug("deleting subject condition set", slog.String("id", req.Msg.GetId()))

	conditionSetID := req.Msg.GetId()
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeConditionSet,
		ObjectID:   conditionSetID,
	}

	_, err := s.dbClient.DeleteSubjectConditionSet(ctx, conditionSetID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", conditionSetID))
	}

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.SubjectConditionSet = &policy.SubjectConditionSet{
		Id: conditionSetID,
	}
	return connect.NewResponse(rsp), nil
}

func (s SubjectMappingService) DeleteAllUnmappedSubjectConditionSets(ctx context.Context,
	_ *connect.Request[sm.DeleteAllUnmappedSubjectConditionSetsRequest],
) (*connect.Response[sm.DeleteAllUnmappedSubjectConditionSetsResponse], error) {
	rsp := &sm.DeleteAllUnmappedSubjectConditionSetsResponse{}
	s.logger.Debug("deleting all unmapped subject condition sets")

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeConditionSet,
	}

	deleted, err := s.dbClient.DeleteAllUnmappedSubjectConditionSets(ctx)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed)
	}

	// Log each pruned subject condition set to audit
	for _, scs := range deleted {
		auditParams.ObjectID = scs.GetId()
		s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	}

	rsp.SubjectConditionSets = deleted
	return connect.NewResponse(rsp), nil
}
