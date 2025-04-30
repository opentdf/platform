package keymanagement

import (
	"context"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy"
	keyMgmtProto "github.com/opentdf/platform/protocol/go/policy/keymanagement"
	keyMgmtConnect "github.com/opentdf/platform/protocol/go/policy/keymanagement/keymanagementconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type Service struct {
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
	config   *policyconfig.Config
}

func OnConfigUpdate(svc *Service) serviceregistry.OnConfigUpdateHook {
	return func(_ context.Context, cfg config.ServiceConfig) error {
		sharedCfg, err := policyconfig.GetSharedPolicyConfig(cfg)
		if err != nil {
			return fmt.Errorf("failed to get shared policy config: %w", err)
		}
		svc.config = sharedCfg
		svc.dbClient = policydb.NewClient(svc.dbClient.Client, svc.logger, int32(sharedCfg.ListRequestLimitMax), int32(sharedCfg.ListRequestLimitDefault))
		svc.logger.Info("key management service config reloaded")
		return nil
	}
}

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[keyMgmtConnect.KeyManagementServiceHandler] {
	return &serviceregistry.Service[keyMgmtConnect.KeyManagementServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[keyMgmtConnect.KeyManagementServiceHandler]{
			Namespace:      ns,
			DB:             dbRegister,
			ServiceDesc:    &keyMgmtProto.KeyManagementService_ServiceDesc,
			ConnectRPCFunc: keyMgmtConnect.NewKeyManagementServiceHandler,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (keyMgmtConnect.KeyManagementServiceHandler, serviceregistry.HandlerServer) {
				cfg, err := policyconfig.GetSharedPolicyConfig(srp.Config)
				if err != nil {
					srp.Logger.Error("Failed to get shared policy config", slog.String("error", err.Error()))
					panic(err)
				}
				ksvc := &Service{
					dbClient: policydb.NewClient(srp.DBClient, srp.Logger, int32(cfg.ListRequestLimitMax), int32(cfg.ListRequestLimitDefault)),
					logger:   srp.Logger,
					config:   cfg,
				}
				return ksvc, nil
			},
		},
	}
}

func (ksvc Service) CreateProviderConfig(ctx context.Context, req *connect.Request[keyMgmtProto.CreateProviderConfigRequest]) (*connect.Response[keyMgmtProto.CreateProviderConfigResponse], error) {
	rsp := &keyMgmtProto.CreateProviderConfigResponse{}

	ksvc.logger.Debug("Creating Provider Config")

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeKeyManagementProviderConfig,
	}

	err := ksvc.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		pc, err := txClient.CreateProviderConfig(ctx, req.Msg)
		if err != nil {
			ksvc.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return err
		}

		auditParams.ObjectID = pc.GetId()
		auditParams.Original = &policy.KeyProviderConfig{
			Id:       pc.GetId(),
			Name:     pc.GetName(),
			Metadata: pc.GetMetadata(),
		}
		ksvc.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

		rsp.ProviderConfig = pc
		return nil
	})
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("keyManagementService", req.Msg.GetName()))
	}

	return connect.NewResponse(rsp), nil
}

func (ksvc Service) GetProviderConfig(ctx context.Context, req *connect.Request[keyMgmtProto.GetProviderConfigRequest]) (*connect.Response[keyMgmtProto.GetProviderConfigResponse], error) {
	rsp := &keyMgmtProto.GetProviderConfigResponse{}

	switch req := req.Msg.GetIdentifier().(type) {
	case *keyMgmtProto.GetProviderConfigRequest_Id:
		ksvc.logger.Debug("Getting Provider config by ID", slog.String("ID", req.Id))
	case *keyMgmtProto.GetProviderConfigRequest_Name:
		ksvc.logger.Debug("Getting Provider config by Name", slog.String("Name", req.Name))
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, nil)
	}

	pc, err := ksvc.dbClient.GetProviderConfig(ctx, req.Msg.GetIdentifier())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("keyManagementService", req.Msg.String()))
	}

	rsp.ProviderConfig = pc
	return connect.NewResponse(rsp), nil
}

func (ksvc Service) ListProviderConfigs(ctx context.Context, req *connect.Request[keyMgmtProto.ListProviderConfigsRequest]) (*connect.Response[keyMgmtProto.ListProviderConfigsResponse], error) {
	ksvc.logger.Debug("Listing Provider Configs")

	resp, err := ksvc.dbClient.ListProviderConfigs(ctx, req.Msg.GetPagination())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("keyManagementService", req.Msg.String()))
	}

	return connect.NewResponse(resp), nil
}

func (ksvc Service) UpdateProviderConfig(ctx context.Context, req *connect.Request[keyMgmtProto.UpdateProviderConfigRequest]) (*connect.Response[keyMgmtProto.UpdateProviderConfigResponse], error) {
	rsp := &keyMgmtProto.UpdateProviderConfigResponse{}
	providerConfigID := req.Msg.GetId()

	ksvc.logger.Debug("Updating Provider Config", slog.String("id", req.Msg.GetId()))

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeKeyManagementProviderConfig,
		ObjectID:   providerConfigID,
	}

	original, err := ksvc.dbClient.GetProviderConfig(ctx, &keyMgmtProto.GetProviderConfigRequest_Id{
		Id: providerConfigID,
	})
	if err != nil {
		ksvc.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", providerConfigID))
	}

	err = ksvc.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		pc, err := txClient.UpdateProviderConfig(ctx, req.Msg)
		if err != nil {
			ksvc.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return err
		}

		// Lets not log the full provider config, leave off config json
		// in case it contains sensitive information
		auditParams.Original = &policy.KeyProviderConfig{
			Id:       original.GetId(),
			Name:     original.GetName(),
			Metadata: original.GetMetadata(),
		}
		auditParams.Updated = &policy.KeyProviderConfig{
			Id:       pc.GetId(),
			Name:     pc.GetName(),
			Metadata: pc.GetMetadata(),
		}
		ksvc.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
		rsp.ProviderConfig = pc

		return nil
	})
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("keyManagementService", req.Msg.GetId()))
	}

	return connect.NewResponse(rsp), nil
}

func (ksvc Service) DeleteProviderConfig(ctx context.Context, req *connect.Request[keyMgmtProto.DeleteProviderConfigRequest]) (*connect.Response[keyMgmtProto.DeleteProviderConfigResponse], error) {
	rsp := &keyMgmtProto.DeleteProviderConfigResponse{}

	ksvc.logger.Debug("Deleting Provider Config", slog.String("id", req.Msg.GetId()))

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeKeyManagementProviderConfig,
	}

	pc, err := ksvc.dbClient.DeleteProviderConfig(ctx, req.Msg.GetId())
	if err != nil {
		ksvc.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("keyManagementService", req.Msg.GetId()))
	}

	auditParams.ObjectID = pc.GetId()
	auditParams.Original = &policy.KeyProviderConfig{
		Id:       pc.GetId(),
		Name:     pc.GetName(),
		Metadata: pc.GetMetadata(),
	}
	ksvc.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.ProviderConfig = pc

	return connect.NewResponse(rsp), nil
}
