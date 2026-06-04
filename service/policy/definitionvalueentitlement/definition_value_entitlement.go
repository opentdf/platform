package definitionvalueentitlement

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	dvem "github.com/opentdf/platform/protocol/go/policy/definitionvalueentitlement"
	"github.com/opentdf/platform/protocol/go/policy/definitionvalueentitlement/definitionvalueentitlementconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type DefinitionValueEntitlementMappingService struct { //nolint:revive // descriptive name mirrors the policy object
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
	config   *policyconfig.Config
}

func OnConfigUpdate(svc *DefinitionValueEntitlementMappingService) serviceregistry.OnConfigUpdateHook {
	return func(_ context.Context, cfg config.ServiceConfig) error {
		sharedCfg, err := policyconfig.GetSharedPolicyConfig(cfg)
		if err != nil {
			return fmt.Errorf("failed to get shared policy config: %w", err)
		}
		svc.config = sharedCfg
		svc.dbClient = policydb.NewClient(svc.dbClient.Client, svc.logger, int32(sharedCfg.ListRequestLimitMax), int32(sharedCfg.ListRequestLimitDefault))
		svc.logger.Info("definition value entitlement mapping service config reloaded")
		return nil
	}
}

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[definitionvalueentitlementconnect.DefinitionValueEntitlementMappingServiceHandler] {
	svc := new(DefinitionValueEntitlementMappingService)
	onUpdateConfigHook := OnConfigUpdate(svc)

	return &serviceregistry.Service[definitionvalueentitlementconnect.DefinitionValueEntitlementMappingServiceHandler]{
		Close: svc.Close,
		ServiceOptions: serviceregistry.ServiceOptions[definitionvalueentitlementconnect.DefinitionValueEntitlementMappingServiceHandler]{
			Namespace:      ns,
			DB:             dbRegister,
			ServiceDesc:    &dvem.DefinitionValueEntitlementMappingService_ServiceDesc,
			ConnectRPCFunc: definitionvalueentitlementconnect.NewDefinitionValueEntitlementMappingServiceHandler,
			OnConfigUpdate: onUpdateConfigHook,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (definitionvalueentitlementconnect.DefinitionValueEntitlementMappingServiceHandler, serviceregistry.HandlerServer) {
				logger := srp.Logger
				cfg, err := policyconfig.GetSharedPolicyConfig(srp.Config)
				if err != nil {
					logger.Error("error getting definition value entitlement mapping service policy config", slog.String("error", err.Error()))
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
func (s *DefinitionValueEntitlementMappingService) Close() {
	s.logger.Info("gracefully shutting down definition value entitlement mapping service")
	s.dbClient.Close()
}

func (s DefinitionValueEntitlementMappingService) CreateDefinitionValueEntitlementMapping(ctx context.Context,
	req *connect.Request[dvem.CreateDefinitionValueEntitlementMappingRequest],
) (*connect.Response[dvem.CreateDefinitionValueEntitlementMappingResponse], error) {
	rsp := &dvem.CreateDefinitionValueEntitlementMappingResponse{}
	s.logger.DebugContext(ctx, "creating definition value entitlement mapping")
	if s.config.NamespacedPolicy && req.Msg.GetNamespaceId() == "" && req.Msg.GetNamespaceFqn() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("either namespace_id or namespace_fqn must be provided"))
	}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeDefinitionValueEntitlementMapping,
	}

	// Creation may involve action or SubjectConditionSet creation, so use a transaction.
	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		mapping, err := txClient.CreateDefinitionValueEntitlementMapping(ctx, req.Msg)
		if err != nil {
			s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return err
		}

		auditParams.ObjectID = mapping.GetId()
		auditParams.Original = mapping
		s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

		rsp.DefinitionValueEntitlementMapping = mapping
		return nil
	})
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextCreationFailed, slog.String("definitionValueEntitlementMapping", req.Msg.String()))
	}
	return connect.NewResponse(rsp), nil
}

func (s DefinitionValueEntitlementMappingService) ListDefinitionValueEntitlementMappings(ctx context.Context,
	req *connect.Request[dvem.ListDefinitionValueEntitlementMappingsRequest],
) (*connect.Response[dvem.ListDefinitionValueEntitlementMappingsResponse], error) {
	s.logger.DebugContext(ctx, "listing definition value entitlement mappings")

	rsp, err := s.dbClient.ListDefinitionValueEntitlementMappings(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextListRetrievalFailed)
	}
	return connect.NewResponse(rsp), nil
}

func (s DefinitionValueEntitlementMappingService) GetDefinitionValueEntitlementMapping(ctx context.Context,
	req *connect.Request[dvem.GetDefinitionValueEntitlementMappingRequest],
) (*connect.Response[dvem.GetDefinitionValueEntitlementMappingResponse], error) {
	s.logger.DebugContext(ctx, "getting definition value entitlement mapping", slog.String("id", req.Msg.GetId()))

	mapping, err := s.dbClient.GetDefinitionValueEntitlementMapping(ctx, req.Msg.GetId())
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", req.Msg.GetId()))
	}
	return connect.NewResponse(&dvem.GetDefinitionValueEntitlementMappingResponse{DefinitionValueEntitlementMapping: mapping}), nil
}

func (s DefinitionValueEntitlementMappingService) UpdateDefinitionValueEntitlementMapping(ctx context.Context,
	req *connect.Request[dvem.UpdateDefinitionValueEntitlementMappingRequest],
) (*connect.Response[dvem.UpdateDefinitionValueEntitlementMappingResponse], error) {
	rsp := &dvem.UpdateDefinitionValueEntitlementMappingResponse{}
	id := req.Msg.GetId()
	s.logger.DebugContext(ctx, "updating definition value entitlement mapping", slog.String("id", id))

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeDefinitionValueEntitlementMapping,
		ObjectID:   id,
	}

	original, err := s.dbClient.GetDefinitionValueEntitlementMapping(ctx, id)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
	}

	updated, err := s.dbClient.UpdateDefinitionValueEntitlementMapping(ctx, req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("id", id), slog.String("definitionValueEntitlementMapping", req.Msg.String()))
	}

	auditParams.Original = original
	auditParams.Updated = updated
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.DefinitionValueEntitlementMapping = updated
	return connect.NewResponse(rsp), nil
}

func (s DefinitionValueEntitlementMappingService) DeleteDefinitionValueEntitlementMapping(ctx context.Context,
	req *connect.Request[dvem.DeleteDefinitionValueEntitlementMappingRequest],
) (*connect.Response[dvem.DeleteDefinitionValueEntitlementMappingResponse], error) {
	rsp := &dvem.DeleteDefinitionValueEntitlementMappingResponse{}
	id := req.Msg.GetId()
	s.logger.DebugContext(ctx, "deleting definition value entitlement mapping", slog.String("id", id))

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeDefinitionValueEntitlementMapping,
		ObjectID:   id,
	}

	deleted, err := s.dbClient.DeleteDefinitionValueEntitlementMapping(ctx, id)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeletionFailed, slog.String("id", id))
	}

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	rsp.DefinitionValueEntitlementMapping = deleted
	return connect.NewResponse(rsp), nil
}
