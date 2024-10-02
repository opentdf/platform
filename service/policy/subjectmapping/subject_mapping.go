package subjectmapping

import (
	"context"
	"log/slog"
	"net/http"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping/subjectmappingconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type SubjectMappingService struct { //nolint:revive // SubjectMappingService is a valid name for this struct
	subjectmapping.UnimplementedSubjectMappingServiceServer
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
}

func NewRegistration(ns string, dbregister serviceregistry.DBRegister) *serviceregistry.Service[subjectmappingconnect.SubjectMappingServiceHandler] {
	return &serviceregistry.Service[subjectmappingconnect.SubjectMappingServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[subjectmappingconnect.SubjectMappingServiceHandler]{
			Namespace:   ns,
			DB:          dbregister,
			ServiceDesc: &subjectmapping.SubjectMappingService_ServiceDesc,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (subjectmappingconnect.SubjectMappingServiceHandler, serviceregistry.HandlerServer) {
				ss := &SubjectMappingService{dbClient: policydb.NewClient(srp.DBClient, srp.Logger), logger: srp.Logger}
				return ss, func(_ context.Context, _ *http.ServeMux, _ any) {}
			},
			ConnectRPCFunc: subjectmappingconnect.NewSubjectMappingServiceHandler,
		},
	}
}

/* ---------------------------------------------------
 * ----------------- SubjectMappings -----------------
 * --------------------------------------------------*/

func (s SubjectMappingService) CreateSubjectMapping(ctx context.Context,
	req *connect.Request[subjectmapping.CreateSubjectMappingRequest],
) (*connect.Response[subjectmapping.CreateSubjectMappingResponse], error) {
	r := req.Msg
	rsp := &subjectmapping.CreateSubjectMappingResponse{}
	s.logger.Debug("creating subject mapping")

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeSubjectMapping,
	}

	sm, err := s.dbClient.CreateSubjectMapping(ctx, r)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("subjectMapping", r.String()))
	}

	auditParams.ObjectID = sm.GetId()
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.SubjectMapping = sm
	return &connect.Response[subjectmapping.CreateSubjectMappingResponse]{Msg: rsp}, nil
}

func (s SubjectMappingService) ListSubjectMappings(ctx context.Context,
	_ *connect.Request[subjectmapping.ListSubjectMappingsRequest],
) (*connect.Response[subjectmapping.ListSubjectMappingsResponse], error) {
	rsp := &subjectmapping.ListSubjectMappingsResponse{}
	s.logger.Debug("listing subject mappings")

	mappings, err := s.dbClient.ListSubjectMappings(ctx)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	rsp.SubjectMappings = mappings
	return &connect.Response[subjectmapping.ListSubjectMappingsResponse]{Msg: rsp}, nil
}

func (s SubjectMappingService) GetSubjectMapping(ctx context.Context,
	req *connect.Request[subjectmapping.GetSubjectMappingRequest],
) (*connect.Response[subjectmapping.GetSubjectMappingResponse], error) {
	r := req.Msg
	rsp := &subjectmapping.GetSubjectMappingResponse{}
	s.logger.Debug("getting subject mapping", slog.String("id", r.GetId()))

	mapping, err := s.dbClient.GetSubjectMapping(ctx, r.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", r.GetId()))
	}

	rsp.SubjectMapping = mapping
	return &connect.Response[subjectmapping.GetSubjectMappingResponse]{Msg: rsp}, nil
}

func (s SubjectMappingService) UpdateSubjectMapping(ctx context.Context,
	req *connect.Request[subjectmapping.UpdateSubjectMappingRequest],
) (*connect.Response[subjectmapping.UpdateSubjectMappingResponse], error) {
	r := req.Msg
	rsp := &subjectmapping.UpdateSubjectMappingResponse{}
	subjectMappingID := r.GetId()

	s.logger.Debug("updating subject mapping", slog.String("subjectMapping", r.String()))

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeSubjectMapping,
		ObjectID:   subjectMappingID,
	}

	originalSM, err := s.dbClient.GetSubjectMapping(ctx, subjectMappingID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", subjectMappingID))
	}

	item, err := s.dbClient.UpdateSubjectMapping(ctx, r)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", r.GetId()), slog.String("subjectMapping fields", r.String()))
	}

	// UpdateSubjectMapping returns only the ID of the subject mapping so we need
	// to fetch the updated subject mapping to compute the diff for audit
	updatedSM, err := s.dbClient.GetSubjectMapping(ctx, subjectMappingID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", subjectMappingID))
	}

	auditParams.Original = originalSM
	auditParams.Updated = updatedSM
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.SubjectMapping = item
	return &connect.Response[subjectmapping.UpdateSubjectMappingResponse]{Msg: rsp}, nil
}

func (s SubjectMappingService) DeleteSubjectMapping(ctx context.Context,
	req *connect.Request[subjectmapping.DeleteSubjectMappingRequest],
) (*connect.Response[subjectmapping.DeleteSubjectMappingResponse], error) {
	r := req.Msg
	rsp := &subjectmapping.DeleteSubjectMappingResponse{}
	s.logger.Debug("deleting subject mapping", slog.String("id", r.GetId()))

	subjectMappingID := r.GetId()
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeSubjectMapping,
		ObjectID:   subjectMappingID,
	}

	sm, err := s.dbClient.DeleteSubjectMapping(ctx, subjectMappingID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", subjectMappingID))
	}

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.SubjectMapping = sm
	return &connect.Response[subjectmapping.DeleteSubjectMappingResponse]{Msg: rsp}, nil
}

func (s SubjectMappingService) MatchSubjectMappings(ctx context.Context,
	req *connect.Request[subjectmapping.MatchSubjectMappingsRequest],
) (*connect.Response[subjectmapping.MatchSubjectMappingsResponse], error) {
	r := req.Msg
	rsp := &subjectmapping.MatchSubjectMappingsResponse{}
	s.logger.Debug("matching subject mappings", slog.Any("subjectProperties", r.GetSubjectProperties()))

	smList, err := s.dbClient.GetMatchedSubjectMappings(ctx, r.GetSubjectProperties())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.Any("subjectProperties", r.GetSubjectProperties()))
	}

	rsp.SubjectMappings = smList

	return &connect.Response[subjectmapping.MatchSubjectMappingsResponse]{Msg: rsp}, nil
}

/* --------------------------------------------------------
 * ----------------- SubjectConditionSets -----------------
 * -------------------------------------------------------*/

func (s SubjectMappingService) GetSubjectConditionSet(ctx context.Context,
	req *connect.Request[subjectmapping.GetSubjectConditionSetRequest],
) (*connect.Response[subjectmapping.GetSubjectConditionSetResponse], error) {
	r := req.Msg
	rsp := &subjectmapping.GetSubjectConditionSetResponse{}
	s.logger.Debug("getting subject condition set", slog.String("id", r.GetId()))

	conditionSet, err := s.dbClient.GetSubjectConditionSet(ctx, r.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", r.GetId()))
	}

	rsp.SubjectConditionSet = conditionSet
	return &connect.Response[subjectmapping.GetSubjectConditionSetResponse]{Msg: rsp}, nil
}

func (s SubjectMappingService) ListSubjectConditionSets(ctx context.Context,
	_ *connect.Request[subjectmapping.ListSubjectConditionSetsRequest],
) (*connect.Response[subjectmapping.ListSubjectConditionSetsResponse], error) {
	rsp := &subjectmapping.ListSubjectConditionSetsResponse{}
	s.logger.Debug("listing subject condition sets")

	conditionSets, err := s.dbClient.ListSubjectConditionSets(ctx)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	rsp.SubjectConditionSets = conditionSets
	return &connect.Response[subjectmapping.ListSubjectConditionSetsResponse]{Msg: rsp}, nil
}

func (s SubjectMappingService) CreateSubjectConditionSet(ctx context.Context,
	req *connect.Request[subjectmapping.CreateSubjectConditionSetRequest],
) (*connect.Response[subjectmapping.CreateSubjectConditionSetResponse], error) {
	r := req.Msg
	rsp := &subjectmapping.CreateSubjectConditionSetResponse{}
	s.logger.Debug("creating subject condition set", slog.String("subjectConditionSet", r.String()))

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeConditionSet,
	}

	conditionSet, err := s.dbClient.CreateSubjectConditionSet(ctx, r.GetSubjectConditionSet())
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("subjectConditionSet", r.String()))
	}

	auditParams.ObjectID = conditionSet.GetId()
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.SubjectConditionSet = conditionSet
	return &connect.Response[subjectmapping.CreateSubjectConditionSetResponse]{Msg: rsp}, nil
}

func (s SubjectMappingService) UpdateSubjectConditionSet(ctx context.Context,
	req *connect.Request[subjectmapping.UpdateSubjectConditionSetRequest],
) (*connect.Response[subjectmapping.UpdateSubjectConditionSetResponse], error) {
	r := req.Msg
	rsp := &subjectmapping.UpdateSubjectConditionSetResponse{}
	s.logger.Debug("updating subject condition set", slog.String("subjectConditionSet", r.String()))

	subjectConditionSetID := r.GetId()
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeConditionSet,
		ObjectID:   subjectConditionSetID,
	}

	originalConditionSet, err := s.dbClient.GetSubjectConditionSet(ctx, subjectConditionSetID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", subjectConditionSetID))
	}

	item, err := s.dbClient.UpdateSubjectConditionSet(ctx, r)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", r.GetId()), slog.String("subjectConditionSet fields", r.String()))
	}

	// UpdateSubjectConditionSet returns only the ID of the subject condition set so we need
	// to fetch the updated subject condition set to compute the diff for audit
	updatedConditionSet, err := s.dbClient.GetSubjectConditionSet(ctx, subjectConditionSetID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", subjectConditionSetID))
	}

	auditParams.Original = originalConditionSet
	auditParams.Updated = updatedConditionSet
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.SubjectConditionSet = item
	return &connect.Response[subjectmapping.UpdateSubjectConditionSetResponse]{Msg: rsp}, nil
}

func (s SubjectMappingService) DeleteSubjectConditionSet(ctx context.Context,
	req *connect.Request[subjectmapping.DeleteSubjectConditionSetRequest],
) (*connect.Response[subjectmapping.DeleteSubjectConditionSetResponse], error) {
	r := req.Msg
	rsp := &subjectmapping.DeleteSubjectConditionSetResponse{}
	s.logger.Debug("deleting subject condition set", slog.String("id", r.GetId()))

	conditionSetID := r.GetId()
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeConditionSet,
		ObjectID:   conditionSetID,
	}

	conditionSet, err := s.dbClient.DeleteSubjectConditionSet(ctx, conditionSetID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", conditionSetID))
	}

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.SubjectConditionSet = conditionSet
	return &connect.Response[subjectmapping.DeleteSubjectConditionSetResponse]{Msg: rsp}, nil
}
