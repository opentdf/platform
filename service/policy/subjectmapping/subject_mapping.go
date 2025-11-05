package subjectmapping

import (
	"context"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy"
	sm "github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping/subjectmappingconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/config"
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

func OnConfigUpdate(smSvc *SubjectMappingService) serviceregistry.OnConfigUpdateHook {
	return func(_ context.Context, cfg config.ServiceConfig) error {
		sharedCfg, err := policyconfig.GetSharedPolicyConfig(cfg)
		if err != nil {
			return fmt.Errorf("failed to get shared policy config: %w", err)
		}
		smSvc.config = sharedCfg
		smSvc.dbClient = policydb.NewClient(smSvc.dbClient.Client, smSvc.logger, int32(sharedCfg.ListRequestLimitMax), int32(sharedCfg.ListRequestLimitDefault))

		smSvc.logger.Info("subject mapping service config reloaded")

		return nil
	}
}

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[subjectmappingconnect.SubjectMappingServiceHandler] {
	smSvc := new(SubjectMappingService)
	onUpdateConfigHook := OnConfigUpdate(smSvc)

	return &serviceregistry.Service[subjectmappingconnect.SubjectMappingServiceHandler]{
		Close: smSvc.Close,
		ServiceOptions: serviceregistry.ServiceOptions[subjectmappingconnect.SubjectMappingServiceHandler]{
			Namespace:      ns,
			DB:             dbRegister,
			ServiceDesc:    &sm.SubjectMappingService_ServiceDesc,
			ConnectRPCFunc: subjectmappingconnect.NewSubjectMappingServiceHandler,
			OnConfigUpdate: onUpdateConfigHook,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (subjectmappingconnect.SubjectMappingServiceHandler, serviceregistry.HandlerServer) {
				logger := srp.Logger
				cfg, err := policyconfig.GetSharedPolicyConfig(srp.Config)
				if err != nil {
					logger.Error("error getting subjectmapping service policy config", slog.String("error", err.Error()))
					panic(err)
				}

				smSvc.logger = logger
				smSvc.dbClient = policydb.NewClient(srp.DBClient, logger, int32(cfg.ListRequestLimitMax), int32(cfg.ListRequestLimitDefault))
				smSvc.config = cfg
				return smSvc, nil
			},
		},
	}
}

// Close gracefully shuts down the service, closing the database client.
func (s *SubjectMappingService) Close() {
	s.logger.Info("gracefully shutting down subject mapping service")
	s.dbClient.Close()
}

/* ---------------------------------------------------
 * ----------------- SubjectMappings -----------------
 * --------------------------------------------------*/

func (s SubjectMappingService) CreateSubjectMapping(ctx context.Context,
	req *connect.Request[sm.CreateSubjectMappingRequest],
) (*connect.Response[sm.CreateSubjectMappingResponse], error) {
	rsp := &sm.CreateSubjectMappingResponse{}
	s.logger.DebugContext(ctx, "creating subject mapping")

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeSubjectMapping,
	}

	// SM Creation may involve action creation or SCS creation, so utilize a transaction
	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		subjectMapping, err := txClient.CreateSubjectMapping(ctx, req.Msg)
		if err != nil {
			s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return err
		}

		auditParams.ObjectID = subjectMapping.GetId()
		auditParams.Original = subjectMapping
		s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

		rsp.SubjectMapping = subjectMapping

		return nil
	})
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextCreationFailed, slog.String("subjectMapping", req.Msg.String()))
	}
	return connect.NewResponse(rsp), nil
}

func (s SubjectMappingService) ListSubjectMappings(ctx context.Context,
	req *connect.Request[sm.ListSubjectMappingsRequest],
) (*connect.Response[sm.ListSubjectMappingsResponse], error) {
	s.logger.DebugContext(ctx, "listing subject mappings")

	rsp, err := s.dbClient.ListSubjectMappings(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextListRetrievalFailed)
	}

	return connect.NewResponse(rsp), nil
}

func (s SubjectMappingService) GetSubjectMapping(ctx context.Context,
	req *connect.Request[sm.GetSubjectMappingRequest],
) (*connect.Response[sm.GetSubjectMappingResponse], error) {
	rsp := &sm.GetSubjectMappingResponse{}
	s.logger.DebugContext(ctx, "getting subject mapping", slog.String("id", req.Msg.GetId()))

	mapping, err := s.dbClient.GetSubjectMapping(ctx, req.Msg.GetId())
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", req.Msg.GetId()))
	}

	rsp.SubjectMapping = mapping
	return connect.NewResponse(rsp), nil
}

func (s SubjectMappingService) UpdateSubjectMapping(ctx context.Context,
	req *connect.Request[sm.UpdateSubjectMappingRequest],
) (*connect.Response[sm.UpdateSubjectMappingResponse], error) {
	rsp := &sm.UpdateSubjectMappingResponse{}
	subjectMappingID := req.Msg.GetId()

	s.logger.DebugContext(ctx, "updating subject mapping", slog.Any("subject_mapping_update", req.Msg))

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeSubjectMapping,
		ObjectID:   subjectMappingID,
	}

	// SM Update may involve action update or SCS update, so utilize a transaction
	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		original, err := txClient.GetSubjectMapping(ctx, subjectMappingID)
		if err != nil {
			s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", subjectMappingID))
		}

		updated, err := txClient.UpdateSubjectMapping(ctx, req.Msg)
		if err != nil {
			s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("id", req.Msg.GetId()), slog.String("subject_mapping_fields", req.Msg.String()))
		}

		auditParams.Original = original
		auditParams.Updated = updated
		s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

		rsp.SubjectMapping = &policy.SubjectMapping{
			Id: subjectMappingID,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(rsp), nil
}

func (s SubjectMappingService) DeleteSubjectMapping(ctx context.Context,
	req *connect.Request[sm.DeleteSubjectMappingRequest],
) (*connect.Response[sm.DeleteSubjectMappingResponse], error) {
	rsp := &sm.DeleteSubjectMappingResponse{}
	s.logger.DebugContext(ctx, "deleting subject mapping", slog.String("id", req.Msg.GetId()))

	subjectMappingID := req.Msg.GetId()
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeSubjectMapping,
		ObjectID:   subjectMappingID,
	}

	_, err := s.dbClient.DeleteSubjectMapping(ctx, subjectMappingID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeletionFailed, slog.String("id", subjectMappingID))
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
	s.logger.DebugContext(ctx, "matching subject mappings", slog.Any("subject_properties", req.Msg.GetSubjectProperties()))

	smList, err := s.dbClient.GetMatchedSubjectMappings(ctx, req.Msg.GetSubjectProperties())
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.Any("subjectProperties", req.Msg.GetSubjectProperties()))
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
	s.logger.DebugContext(ctx, "getting subject condition set", slog.String("id", req.Msg.GetId()))

	conditionSet, err := s.dbClient.GetSubjectConditionSet(ctx, req.Msg.GetId())
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", req.Msg.GetId()))
	}

	rsp.SubjectConditionSet = conditionSet
	return connect.NewResponse(rsp), nil
}

func (s SubjectMappingService) ListSubjectConditionSets(ctx context.Context,
	req *connect.Request[sm.ListSubjectConditionSetsRequest],
) (*connect.Response[sm.ListSubjectConditionSetsResponse], error) {
	s.logger.DebugContext(ctx, "listing subject condition sets")

	rsp, err := s.dbClient.ListSubjectConditionSets(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextListRetrievalFailed)
	}

	return connect.NewResponse(rsp), nil
}

func (s SubjectMappingService) CreateSubjectConditionSet(ctx context.Context,
	req *connect.Request[sm.CreateSubjectConditionSetRequest],
) (*connect.Response[sm.CreateSubjectConditionSetResponse], error) {
	rsp := &sm.CreateSubjectConditionSetResponse{}
	s.logger.DebugContext(ctx, "creating subject condition set", slog.Any("subject_condition_set", req.Msg))

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeConditionSet,
	}

	var conditionSet *policy.SubjectConditionSet
	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		var err error
		conditionSet, err = txClient.CreateSubjectConditionSet(ctx, req.Msg.GetSubjectConditionSet())
		if err != nil {
			s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return db.StatusifyError(ctx, s.logger, err, db.ErrTextCreationFailed, slog.String("subjectConditionSet", req.Msg.String()))
		}
		return nil
	})
	if err != nil {
		return nil, err
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
	s.logger.DebugContext(ctx, "updating subject condition set", slog.Any("subject_condition_set", req.Msg))

	subjectConditionSetID := req.Msg.GetId()
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeConditionSet,
		ObjectID:   subjectConditionSetID,
	}

	var original, updated *policy.SubjectConditionSet
	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		var err error
		original, err = txClient.GetSubjectConditionSet(ctx, subjectConditionSetID)
		if err != nil {
			s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", subjectConditionSetID))
		}

		updated, err = txClient.UpdateSubjectConditionSet(ctx, req.Msg)
		if err != nil {
			s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("id", req.Msg.GetId()), slog.String("subjectConditionSet fields", req.Msg.String()))
		}

		rsp.SubjectConditionSet = &policy.SubjectConditionSet{
			Id: subjectConditionSetID,
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	auditParams.Original = original
	auditParams.Updated = updated
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	return connect.NewResponse(rsp), nil
}

func (s SubjectMappingService) DeleteSubjectConditionSet(ctx context.Context,
	req *connect.Request[sm.DeleteSubjectConditionSetRequest],
) (*connect.Response[sm.DeleteSubjectConditionSetResponse], error) {
	rsp := &sm.DeleteSubjectConditionSetResponse{}
	s.logger.DebugContext(ctx, "deleting subject condition set", slog.String("id", req.Msg.GetId()))

	conditionSetID := req.Msg.GetId()
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeConditionSet,
		ObjectID:   conditionSetID,
	}

	_, err := s.dbClient.DeleteSubjectConditionSet(ctx, conditionSetID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeletionFailed, slog.String("id", conditionSetID))
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
	s.logger.DebugContext(ctx, "deleting all unmapped subject condition sets")

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeConditionSet,
	}

	deleted, err := s.dbClient.DeleteAllUnmappedSubjectConditionSets(ctx)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeletionFailed)
	}

	// Log each pruned subject condition set to audit
	for _, scs := range deleted {
		auditParams.ObjectID = scs.GetId()
		s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	}

	rsp.SubjectConditionSets = deleted
	return connect.NewResponse(rsp), nil
}
