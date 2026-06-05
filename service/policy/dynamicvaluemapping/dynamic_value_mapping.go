package dynamicvaluemapping

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	dvm "github.com/opentdf/platform/protocol/go/policy/dynamicvaluemapping"
	"github.com/opentdf/platform/protocol/go/policy/dynamicvaluemapping/dynamicvaluemappingconnect"
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

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[dynamicvaluemappingconnect.DynamicValueMappingServiceHandler] {
	svc := new(DynamicValueMappingService)
	onUpdateConfigHook := OnConfigUpdate(svc)

	return &serviceregistry.Service[dynamicvaluemappingconnect.DynamicValueMappingServiceHandler]{
		Close: svc.Close,
		ServiceOptions: serviceregistry.ServiceOptions[dynamicvaluemappingconnect.DynamicValueMappingServiceHandler]{
			Namespace:      ns,
			DB:             dbRegister,
			ServiceDesc:    &dvm.DynamicValueMappingService_ServiceDesc,
			ConnectRPCFunc: dynamicvaluemappingconnect.NewDynamicValueMappingServiceHandler,
			OnConfigUpdate: onUpdateConfigHook,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (dynamicvaluemappingconnect.DynamicValueMappingServiceHandler, serviceregistry.HandlerServer) {
				logger := srp.Logger
				cfg, err := policyconfig.GetSharedPolicyConfig(srp.Config)
				if err != nil {
					logger.Error("error getting dynamic value mapping service policy config", slog.String("error", err.Error()))
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
	req *connect.Request[dvm.CreateDynamicValueMappingRequest],
) (*connect.Response[dvm.CreateDynamicValueMappingResponse], error) {
	rsp := &dvm.CreateDynamicValueMappingResponse{}
	s.logger.DebugContext(ctx, "creating dynamic value mapping")
	if s.config.NamespacedPolicy && req.Msg.GetNamespaceId() == "" && req.Msg.GetNamespaceFqn() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("either namespace_id or namespace_fqn must be provided"))
	}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeDynamicValueMapping,
	}

	// Creation may involve action or SubjectConditionSet creation, so use a transaction.
	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		mapping, err := txClient.CreateDynamicValueMapping(ctx, req.Msg)
		if err != nil {
			s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return err
		}

		auditParams.ObjectID = mapping.GetId()
		auditParams.Original = mapping
		s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

		rsp.DynamicValueMapping = mapping
		return nil
	})
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextCreationFailed, slog.String("dynamicValueMapping", req.Msg.String()))
	}
	return connect.NewResponse(rsp), nil
}

func (s DynamicValueMappingService) ListDynamicValueMappings(ctx context.Context,
	req *connect.Request[dvm.ListDynamicValueMappingsRequest],
) (*connect.Response[dvm.ListDynamicValueMappingsResponse], error) {
	s.logger.DebugContext(ctx, "listing dynamic value mappings")

	rsp, err := s.dbClient.ListDynamicValueMappings(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextListRetrievalFailed)
	}
	return connect.NewResponse(rsp), nil
}

func (s DynamicValueMappingService) GetDynamicValueMapping(ctx context.Context,
	req *connect.Request[dvm.GetDynamicValueMappingRequest],
) (*connect.Response[dvm.GetDynamicValueMappingResponse], error) {
	s.logger.DebugContext(ctx, "getting dynamic value mapping", slog.String("id", req.Msg.GetId()))

	mapping, err := s.dbClient.GetDynamicValueMapping(ctx, req.Msg.GetId())
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", req.Msg.GetId()))
	}
	return connect.NewResponse(&dvm.GetDynamicValueMappingResponse{DynamicValueMapping: mapping}), nil
}

func (s DynamicValueMappingService) UpdateDynamicValueMapping(ctx context.Context,
	req *connect.Request[dvm.UpdateDynamicValueMappingRequest],
) (*connect.Response[dvm.UpdateDynamicValueMappingResponse], error) {
	rsp := &dvm.UpdateDynamicValueMappingResponse{}
	id := req.Msg.GetId()
	s.logger.DebugContext(ctx, "updating dynamic value mapping", slog.String("id", id))

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeDynamicValueMapping,
		ObjectID:   id,
	}

	original, err := s.dbClient.GetDynamicValueMapping(ctx, id)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
	}

	updated, err := s.dbClient.UpdateDynamicValueMapping(ctx, req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("id", id), slog.String("dynamicValueMapping", req.Msg.String()))
	}

	auditParams.Original = original
	auditParams.Updated = updated
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.DynamicValueMapping = updated
	return connect.NewResponse(rsp), nil
}

func (s DynamicValueMappingService) DeleteDynamicValueMapping(ctx context.Context,
	req *connect.Request[dvm.DeleteDynamicValueMappingRequest],
) (*connect.Response[dvm.DeleteDynamicValueMappingResponse], error) {
	rsp := &dvm.DeleteDynamicValueMappingResponse{}
	id := req.Msg.GetId()
	s.logger.DebugContext(ctx, "deleting dynamic value mapping", slog.String("id", id))

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeDynamicValueMapping,
		ObjectID:   id,
	}

	deleted, err := s.dbClient.DeleteDynamicValueMapping(ctx, id)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeletionFailed, slog.String("id", id))
	}

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	rsp.DynamicValueMapping = deleted
	return connect.NewResponse(rsp), nil
}
