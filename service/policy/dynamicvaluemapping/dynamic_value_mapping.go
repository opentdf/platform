package dynamicvaluemapping

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"connectrpc.com/connect/v2"
	dvm "github.com/opentdf/platform/protocol/go/policy/dynamicvaluemapping"
	"github.com/opentdf/platform/protocol/go/policy/dynamicvaluemapping/dynamicvaluemappingconnectv2"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type DynamicValueMappingService struct { //nolint:revive // descriptive name mirrors the policy object
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
	config   *policyconfig.Config
}

var errNamespaceRequired = errors.New("either namespace_id or namespace_fqn must be provided")

func OnConfigUpdate(svc *DynamicValueMappingService) serviceregistry.OnConfigUpdateHook {
	return func(_ context.Context, cfg config.ServiceConfig) error {
		sharedCfg, err := policyconfig.GetSharedPolicyConfig(cfg)
		if err != nil {
			return fmt.Errorf("failed to get shared policy config: %w", err)
		}
		svc.config = sharedCfg
		svc.dbClient = policydb.NewClient(svc.dbClient.Client, svc.logger, int32(sharedCfg.ListRequestLimitMax), int32(sharedCfg.ListRequestLimitDefault))
		svc.logger.Info("dynamic value mapping service config reloaded")
		return nil
	}
}

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[dynamicvaluemappingconnectv2.DynamicValueMappingServiceHandler] {
	svc := new(DynamicValueMappingService)
	onUpdateConfigHook := OnConfigUpdate(svc)

	return &serviceregistry.Service[dynamicvaluemappingconnectv2.DynamicValueMappingServiceHandler]{
		Close: svc.Close,
		ServiceOptions: serviceregistry.ServiceOptions[dynamicvaluemappingconnectv2.DynamicValueMappingServiceHandler]{
			Namespace:              ns,
			DB:                     dbRegister,
			ServiceDesc:            &dvm.DynamicValueMappingService_ServiceDesc,
			ConnectRPCRegisterFunc: dynamicvaluemappingconnectv2.RegisterDynamicValueMappingServiceHandler,
			OnConfigUpdate:         onUpdateConfigHook,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (dynamicvaluemappingconnectv2.DynamicValueMappingServiceHandler, serviceregistry.HandlerServer) {
				logger := srp.Logger
				cfg, err := policyconfig.GetSharedPolicyConfig(srp.Config)
				if err != nil {
					logger.Error("error getting dynamic value mapping service policy config", slog.Any("error", err))
					panic(err)
				}

				svc.logger = logger
				svc.dbClient = policydb.NewClient(srp.DBClient, logger, int32(cfg.ListRequestLimitMax), int32(cfg.ListRequestLimitDefault))
				svc.config = cfg
				return svc, nil
			},
		},
	}
}

// Close gracefully shuts down the service, closing the database client.
func (s *DynamicValueMappingService) Close() {
	s.logger.Info("gracefully shutting down dynamic value mapping service")
	s.dbClient.Close()
}

func (s DynamicValueMappingService) CreateDynamicValueMapping(ctx context.Context,
	req *dvm.CreateDynamicValueMappingRequest,
) (*dvm.CreateDynamicValueMappingResponse, error) {
	rsp := &dvm.CreateDynamicValueMappingResponse{}
	s.logger.DebugContext(ctx, "creating dynamic value mapping")
	if req.GetNamespaceId() == "" && req.GetNamespaceFqn() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errNamespaceRequired.Error()).WithCause(errNamespaceRequired)
	}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeDynamicValueMapping,
	}

	// Creation may involve action or SubjectConditionSet creation, so use a transaction.
	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		mapping, err := txClient.CreateDynamicValueMapping(ctx, req)
		if err != nil {
			return err
		}

		auditParams.ObjectID = mapping.GetId()
		auditParams.Original = mapping

		rsp.DynamicValueMapping = mapping
		return nil
	})
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextCreationFailed, slog.String("dynamic_value_mapping", req.String()))
	}
	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)
	return rsp, nil
}

func (s DynamicValueMappingService) ListDynamicValueMappings(ctx context.Context,
	req *dvm.ListDynamicValueMappingsRequest,
) (*dvm.ListDynamicValueMappingsResponse, error) {
	s.logger.DebugContext(ctx, "listing dynamic value mappings")

	rsp, err := s.dbClient.ListDynamicValueMappings(ctx, req)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextListRetrievalFailed)
	}
	return rsp, nil
}

func (s DynamicValueMappingService) GetDynamicValueMapping(ctx context.Context,
	req *dvm.GetDynamicValueMappingRequest,
) (*dvm.GetDynamicValueMappingResponse, error) {
	s.logger.DebugContext(ctx, "getting dynamic value mapping", slog.String("id", req.GetId()))

	mapping, err := s.dbClient.GetDynamicValueMapping(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}
	return &dvm.GetDynamicValueMappingResponse{DynamicValueMapping: mapping}, nil
}

func (s DynamicValueMappingService) UpdateDynamicValueMapping(ctx context.Context,
	req *dvm.UpdateDynamicValueMappingRequest,
) (*dvm.UpdateDynamicValueMappingResponse, error) {
	rsp := &dvm.UpdateDynamicValueMappingResponse{}
	id := req.GetId()
	s.logger.DebugContext(ctx, "updating dynamic value mapping", slog.String("id", id))

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeDynamicValueMapping,
		ObjectID:   id,
	}

	// Read and update in one transaction so the audited original matches the applied update.
	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		original, err := txClient.GetDynamicValueMapping(ctx, id)
		if err != nil {
			return err
		}

		updated, err := txClient.UpdateDynamicValueMapping(ctx, req)
		if err != nil {
			return err
		}

		auditParams.Original = original
		auditParams.Updated = updated

		rsp.DynamicValueMapping = updated
		return nil
	})
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("id", id), slog.String("dynamic_value_mapping", req.String()))
	}
	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	return rsp, nil
}

func (s DynamicValueMappingService) DeleteDynamicValueMapping(ctx context.Context,
	req *dvm.DeleteDynamicValueMappingRequest,
) (*dvm.DeleteDynamicValueMappingResponse, error) {
	rsp := &dvm.DeleteDynamicValueMappingResponse{}
	id := req.GetId()
	s.logger.DebugContext(ctx, "deleting dynamic value mapping", slog.String("id", id))

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeDynamicValueMapping,
		ObjectID:   id,
	}

	deleted, err := s.dbClient.DeleteDynamicValueMapping(ctx, id)
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeletionFailed, slog.String("id", id))
	}

	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)
	rsp.DynamicValueMapping = deleted
	return rsp, nil
}
