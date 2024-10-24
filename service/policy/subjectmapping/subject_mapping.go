package subjectmapping

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/protocol/go/policy"
	sm "github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type SubjectMappingService struct { //nolint:revive // SubjectMappingService is a valid name for this struct
	sm.UnimplementedSubjectMappingServiceServer
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
	config   *policyconfig.Config
}

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		ServiceDesc: &sm.SubjectMappingService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			cfg := policyconfig.GetSharedPolicyConfig(srp)
			return &SubjectMappingService{
					dbClient: policydb.NewClient(srp.DBClient, srp.Logger, int32(cfg.ListRequestLimitMax), int32(cfg.ListRequestLimitDefault)),
					logger:   srp.Logger,
					config:   cfg,
				}, func(ctx context.Context, mux *runtime.ServeMux, s any) error {
					server, ok := s.(sm.SubjectMappingServiceServer)
					if !ok {
						return fmt.Errorf("failed to assert server as sm.SubjectMappingServiceServer")
					}
					return sm.RegisterSubjectMappingServiceHandlerServer(ctx, mux, server)
				}
		},
	}
}

/* ---------------------------------------------------
 * ----------------- SubjectMappings -----------------
 * --------------------------------------------------*/

func (s SubjectMappingService) CreateSubjectMapping(ctx context.Context,
	req *sm.CreateSubjectMappingRequest,
) (*sm.CreateSubjectMappingResponse, error) {
	rsp := &sm.CreateSubjectMappingResponse{}
	s.logger.Debug("creating subject mapping")

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeSubjectMapping,
	}

	sm, err := s.dbClient.CreateSubjectMapping(ctx, req)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("subjectMapping", req.String()))
	}

	auditParams.ObjectID = sm.GetId()
	auditParams.Original = sm
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.SubjectMapping = sm
	return rsp, nil
}

func (s SubjectMappingService) ListSubjectMappings(ctx context.Context,
	r *sm.ListSubjectMappingsRequest,
) (*sm.ListSubjectMappingsResponse, error) {
	s.logger.Debug("listing subject mappings")

	rsp, err := s.dbClient.ListSubjectMappings(ctx, r)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	return rsp, nil
}

func (s SubjectMappingService) GetSubjectMapping(ctx context.Context,
	req *sm.GetSubjectMappingRequest,
) (*sm.GetSubjectMappingResponse, error) {
	rsp := &sm.GetSubjectMappingResponse{}
	s.logger.Debug("getting subject mapping", slog.String("id", req.GetId()))

	mapping, err := s.dbClient.GetSubjectMapping(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}

	rsp.SubjectMapping = mapping
	return rsp, nil
}

func (s SubjectMappingService) UpdateSubjectMapping(ctx context.Context,
	req *sm.UpdateSubjectMappingRequest,
) (*sm.UpdateSubjectMappingResponse, error) {
	rsp := &sm.UpdateSubjectMappingResponse{}
	subjectMappingID := req.GetId()

	s.logger.Debug("updating subject mapping", slog.String("subjectMapping", req.String()))

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

	updated, err := s.dbClient.UpdateSubjectMapping(ctx, req)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()), slog.String("subjectMapping fields", req.String()))
	}

	auditParams.Original = original
	auditParams.Updated = updated
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.SubjectMapping = &policy.SubjectMapping{
		Id: subjectMappingID,
	}
	return rsp, nil
}

func (s SubjectMappingService) DeleteSubjectMapping(ctx context.Context,
	req *sm.DeleteSubjectMappingRequest,
) (*sm.DeleteSubjectMappingResponse, error) {
	rsp := &sm.DeleteSubjectMappingResponse{}
	s.logger.Debug("deleting subject mapping", slog.String("id", req.GetId()))

	subjectMappingID := req.GetId()
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
	return rsp, nil
}

func (s SubjectMappingService) MatchSubjectMappings(ctx context.Context,
	req *sm.MatchSubjectMappingsRequest,
) (*sm.MatchSubjectMappingsResponse, error) {
	rsp := &sm.MatchSubjectMappingsResponse{}
	s.logger.Debug("matching subject mappings", slog.Any("subjectProperties", req.GetSubjectProperties()))

	smList, err := s.dbClient.GetMatchedSubjectMappings(ctx, req.GetSubjectProperties())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.Any("subjectProperties", req.GetSubjectProperties()))
	}

	rsp.SubjectMappings = smList
	return rsp, nil
}

/* --------------------------------------------------------
 * ----------------- SubjectConditionSets -----------------
 * -------------------------------------------------------*/

func (s SubjectMappingService) GetSubjectConditionSet(ctx context.Context,
	req *sm.GetSubjectConditionSetRequest,
) (*sm.GetSubjectConditionSetResponse, error) {
	rsp := &sm.GetSubjectConditionSetResponse{}
	s.logger.Debug("getting subject condition set", slog.String("id", req.GetId()))

	conditionSet, err := s.dbClient.GetSubjectConditionSet(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}

	rsp.SubjectConditionSet = conditionSet
	return rsp, nil
}

func (s SubjectMappingService) ListSubjectConditionSets(ctx context.Context,
	r *sm.ListSubjectConditionSetsRequest,
) (*sm.ListSubjectConditionSetsResponse, error) {
	s.logger.Debug("listing subject condition sets")

	rsp, err := s.dbClient.ListSubjectConditionSets(ctx, r)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	return rsp, nil
}

func (s SubjectMappingService) CreateSubjectConditionSet(ctx context.Context,
	req *sm.CreateSubjectConditionSetRequest,
) (*sm.CreateSubjectConditionSetResponse, error) {
	rsp := &sm.CreateSubjectConditionSetResponse{}
	s.logger.Debug("creating subject condition set", slog.String("subjectConditionSet", req.String()))

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeConditionSet,
	}

	conditionSet, err := s.dbClient.CreateSubjectConditionSet(ctx, req.GetSubjectConditionSet())
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("subjectConditionSet", req.String()))
	}

	auditParams.ObjectID = conditionSet.GetId()
	auditParams.Original = conditionSet
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.SubjectConditionSet = conditionSet
	return rsp, nil
}

func (s SubjectMappingService) UpdateSubjectConditionSet(ctx context.Context,
	req *sm.UpdateSubjectConditionSetRequest,
) (*sm.UpdateSubjectConditionSetResponse, error) {
	rsp := &sm.UpdateSubjectConditionSetResponse{}
	s.logger.Debug("updating subject condition set", slog.String("subjectConditionSet", req.String()))

	subjectConditionSetID := req.GetId()
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

	updated, err := s.dbClient.UpdateSubjectConditionSet(ctx, req)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()), slog.String("subjectConditionSet fields", req.String()))
	}

	auditParams.Original = original
	auditParams.Updated = updated
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.SubjectConditionSet = &policy.SubjectConditionSet{
		Id: subjectConditionSetID,
	}
	return rsp, nil
}

func (s SubjectMappingService) DeleteSubjectConditionSet(ctx context.Context,
	req *sm.DeleteSubjectConditionSetRequest,
) (*sm.DeleteSubjectConditionSetResponse, error) {
	rsp := &sm.DeleteSubjectConditionSetResponse{}
	s.logger.Debug("deleting subject condition set", slog.String("id", req.GetId()))

	conditionSetID := req.GetId()
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
	return rsp, nil
}
