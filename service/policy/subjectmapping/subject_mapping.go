package subjectmapping

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"connectrpc.com/connect/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	sm "github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/service/internal/connectv2/policy/subjectmapping/subjectmappingconnectv2"
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

var errNamespacedPolicyNamespaceRequired = errors.New("either namespace_id or namespace_fqn must be provided")

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

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[subjectmappingconnectv2.SubjectMappingServiceHandler] {
	smSvc := new(SubjectMappingService)
	onUpdateConfigHook := OnConfigUpdate(smSvc)

	return &serviceregistry.Service[subjectmappingconnectv2.SubjectMappingServiceHandler]{
		Close: smSvc.Close,
		ServiceOptions: serviceregistry.ServiceOptions[subjectmappingconnectv2.SubjectMappingServiceHandler]{
			Namespace:              ns,
			DB:                     dbRegister,
			ServiceDesc:            &sm.SubjectMappingService_ServiceDesc,
			ConnectRPCRegisterFunc: subjectmappingconnectv2.RegisterSubjectMappingServiceHandler,
			OnConfigUpdate:         onUpdateConfigHook,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (subjectmappingconnectv2.SubjectMappingServiceHandler, serviceregistry.HandlerServer) {
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
	req *sm.CreateSubjectMappingRequest,
) (*sm.CreateSubjectMappingResponse, error) {
	rsp := &sm.CreateSubjectMappingResponse{}
	s.logger.DebugContext(ctx, "creating subject mapping")
	if s.config.NamespacedPolicy && req.GetNamespaceId() == "" && req.GetNamespaceFqn() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errNamespacedPolicyNamespaceRequired.Error()).WithCause(errNamespacedPolicyNamespaceRequired)
	}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeSubjectMapping,
	}

	// SM Creation may involve action creation or SCS creation, so utilize a transaction
	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		subjectMapping, err := txClient.CreateSubjectMapping(ctx, req)
		if err != nil {
			return err
		}

		auditParams.ObjectID = subjectMapping.GetId()
		auditParams.Original = subjectMapping

		rsp.SubjectMapping = subjectMapping

		return nil
	})
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextCreationFailed, slog.String("subject_mapping", req.String()))
	}
	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)
	return rsp, nil
}

func (s SubjectMappingService) ListSubjectMappings(ctx context.Context,
	req *sm.ListSubjectMappingsRequest,
) (*sm.ListSubjectMappingsResponse, error) {
	s.logger.DebugContext(ctx, "listing subject mappings")

	rsp, err := s.dbClient.ListSubjectMappings(ctx, req)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextListRetrievalFailed)
	}

	return rsp, nil
}

func (s SubjectMappingService) GetSubjectMapping(ctx context.Context,
	req *sm.GetSubjectMappingRequest,
) (*sm.GetSubjectMappingResponse, error) {
	rsp := &sm.GetSubjectMappingResponse{}
	s.logger.DebugContext(ctx, "getting subject mapping", slog.String("id", req.GetId()))

	mapping, err := s.dbClient.GetSubjectMapping(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}

	rsp.SubjectMapping = mapping
	return rsp, nil
}

func (s SubjectMappingService) UpdateSubjectMapping(ctx context.Context,
	req *sm.UpdateSubjectMappingRequest,
) (*sm.UpdateSubjectMappingResponse, error) {
	rsp := &sm.UpdateSubjectMappingResponse{}
	subjectMappingID := req.GetId()

	s.logger.DebugContext(ctx, "updating subject mapping", slog.Any("subject_mapping_update", req))

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeSubjectMapping,
		ObjectID:   subjectMappingID,
	}

	// SM Update may involve action update or SCS update, so utilize a transaction
	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		original, err := txClient.GetSubjectMapping(ctx, subjectMappingID)
		if err != nil {
			return db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", subjectMappingID))
		}

		updated, err := txClient.UpdateSubjectMapping(ctx, req)
		if err != nil {
			return db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()), slog.String("subject_mapping_fields", req.String()))
		}

		auditParams.Original = original
		auditParams.Updated = updated

		rsp.SubjectMapping = &policy.SubjectMapping{
			Id: subjectMappingID,
		}
		return nil
	})
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, err
	}
	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)
	return rsp, nil
}

func (s SubjectMappingService) DeleteSubjectMapping(ctx context.Context,
	req *sm.DeleteSubjectMappingRequest,
) (*sm.DeleteSubjectMappingResponse, error) {
	rsp := &sm.DeleteSubjectMappingResponse{}
	s.logger.DebugContext(ctx, "deleting subject mapping", slog.String("id", req.GetId()))

	subjectMappingID := req.GetId()
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeSubjectMapping,
		ObjectID:   subjectMappingID,
	}

	_, err := s.dbClient.DeleteSubjectMapping(ctx, subjectMappingID)
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeletionFailed, slog.String("id", subjectMappingID))
	}

	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	rsp.SubjectMapping = &policy.SubjectMapping{
		Id: subjectMappingID,
	}
	return rsp, nil
}

func (s SubjectMappingService) MatchSubjectMappings(ctx context.Context,
	req *sm.MatchSubjectMappingsRequest,
) (*sm.MatchSubjectMappingsResponse, error) {
	rsp := &sm.MatchSubjectMappingsResponse{}
	s.logger.DebugContext(ctx, "matching subject mappings", slog.Any("subject_properties", req.GetSubjectProperties()))

	smList, err := s.dbClient.GetMatchedSubjectMappings(ctx, req.GetSubjectProperties())
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.Any("subject_properties", req.GetSubjectProperties()))
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
	s.logger.DebugContext(ctx, "getting subject condition set", slog.String("id", req.GetId()))

	conditionSet, err := s.dbClient.GetSubjectConditionSet(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}

	rsp.SubjectConditionSet = conditionSet
	return rsp, nil
}

func (s SubjectMappingService) ListSubjectConditionSets(ctx context.Context,
	req *sm.ListSubjectConditionSetsRequest,
) (*sm.ListSubjectConditionSetsResponse, error) {
	s.logger.DebugContext(ctx, "listing subject condition sets")

	rsp, err := s.dbClient.ListSubjectConditionSets(ctx, req)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextListRetrievalFailed)
	}

	return rsp, nil
}

func (s SubjectMappingService) CreateSubjectConditionSet(ctx context.Context,
	req *sm.CreateSubjectConditionSetRequest,
) (*sm.CreateSubjectConditionSetResponse, error) {
	rsp := &sm.CreateSubjectConditionSetResponse{}
	s.logger.DebugContext(ctx, "creating subject condition set", slog.Any("subject_condition_set", req))
	if s.config.NamespacedPolicy && req.GetNamespaceId() == "" && req.GetNamespaceFqn() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errNamespacedPolicyNamespaceRequired.Error()).WithCause(errNamespacedPolicyNamespaceRequired)
	}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeConditionSet,
	}

	var conditionSet *policy.SubjectConditionSet
	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		cs, err := txClient.CreateSubjectConditionSet(ctx, req.GetSubjectConditionSet(), req.GetNamespaceId(), req.GetNamespaceFqn())
		if err != nil {
			return db.StatusifyError(ctx, s.logger, err, db.ErrTextCreationFailed, slog.String("subject_condition_set", req.String()))
		}

		conditionSet = cs
		return nil
	})
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, err
	}

	auditParams.ObjectID = conditionSet.GetId()
	auditParams.Original = conditionSet
	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	rsp.SubjectConditionSet = conditionSet

	return rsp, nil
}

func (s SubjectMappingService) UpdateSubjectConditionSet(ctx context.Context,
	req *sm.UpdateSubjectConditionSetRequest,
) (*sm.UpdateSubjectConditionSetResponse, error) {
	rsp := &sm.UpdateSubjectConditionSetResponse{}
	s.logger.DebugContext(ctx, "updating subject condition set", slog.Any("subject_condition_set", req))

	subjectConditionSetID := req.GetId()
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeConditionSet,
		ObjectID:   subjectConditionSetID,
	}

	var original, updated *policy.SubjectConditionSet
	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		orig, err := txClient.GetSubjectConditionSet(ctx, subjectConditionSetID)
		if err != nil {
			return db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", subjectConditionSetID))
		}

		upd, err := txClient.UpdateSubjectConditionSet(ctx, req)
		if err != nil {
			return db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()), slog.String("subject_condition_set_fields", req.String()))
		}

		original = orig
		updated = upd
		rsp.SubjectConditionSet = &policy.SubjectConditionSet{
			Id: subjectConditionSetID,
		}

		return nil
	})
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, err
	}

	auditParams.Original = original
	auditParams.Updated = updated
	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	return rsp, nil
}

func (s SubjectMappingService) DeleteSubjectConditionSet(ctx context.Context,
	req *sm.DeleteSubjectConditionSetRequest,
) (*sm.DeleteSubjectConditionSetResponse, error) {
	rsp := &sm.DeleteSubjectConditionSetResponse{}
	s.logger.DebugContext(ctx, "deleting subject condition set", slog.String("id", req.GetId()))

	conditionSetID := req.GetId()
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeConditionSet,
		ObjectID:   conditionSetID,
	}

	_, err := s.dbClient.DeleteSubjectConditionSet(ctx, conditionSetID)
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeletionFailed, slog.String("id", conditionSetID))
	}

	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	rsp.SubjectConditionSet = &policy.SubjectConditionSet{
		Id: conditionSetID,
	}
	return rsp, nil
}

func (s SubjectMappingService) DeleteAllUnmappedSubjectConditionSets(ctx context.Context,
	_ *sm.DeleteAllUnmappedSubjectConditionSetsRequest,
) (*sm.DeleteAllUnmappedSubjectConditionSetsResponse, error) {
	rsp := &sm.DeleteAllUnmappedSubjectConditionSetsResponse{}
	s.logger.DebugContext(ctx, "deleting all unmapped subject condition sets")

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeConditionSet,
	}

	deleted, err := s.dbClient.DeleteAllUnmappedSubjectConditionSets(ctx)
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeletionFailed)
	}

	// Log each pruned subject condition set to audit
	for _, scs := range deleted {
		auditParams.ObjectID = scs.GetId()
		s.logger.LogPolicyCRUDSuccess(ctx, auditParams)
	}

	rsp.SubjectConditionSets = deleted
	return rsp, nil
}
