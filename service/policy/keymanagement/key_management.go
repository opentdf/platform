package keymanagement

import (
	"context"
	"fmt"
	"log/slog"

	"connectrpc.com/connect/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	keyMgmtProto "github.com/opentdf/platform/protocol/go/policy/keymanagement"
	keyMgmtConnect "github.com/opentdf/platform/protocol/go/policy/keymanagement/keymanagementconnectv2"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
	"github.com/opentdf/platform/service/wellknownconfiguration"
)

type Service struct {
	dbClient            policydb.PolicyDBClient
	logger              *logger.Logger
	config              *policyconfig.Config
	keyManagerFactories []registeredManagers
}

type registeredManagers struct {
	Name        string `json:"name"`
	Description string `json:"description"`
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
	ksvc := new(Service)
	onUpdateConfigHook := OnConfigUpdate(ksvc)

	return &serviceregistry.Service[keyMgmtConnect.KeyManagementServiceHandler]{
		Close: ksvc.Close,
		ServiceOptions: serviceregistry.ServiceOptions[keyMgmtConnect.KeyManagementServiceHandler]{
			Namespace:              ns,
			DB:                     dbRegister,
			ServiceDesc:            &keyMgmtProto.KeyManagementService_ServiceDesc,
			ConnectRPCRegisterFunc: keyMgmtConnect.RegisterKeyManagementServiceHandler,
			OnConfigUpdate:         onUpdateConfigHook,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (keyMgmtConnect.KeyManagementServiceHandler, serviceregistry.HandlerServer) {
				cfg, err := policyconfig.GetSharedPolicyConfig(srp.Config)
				if err != nil {
					srp.Logger.Error("failed to get shared policy config", slog.Any("error", err))
					panic(err)
				}
				ksvc.logger = srp.Logger
				ksvc.config = cfg
				ksvc.dbClient = policydb.NewClient(srp.DBClient, srp.Logger, int32(cfg.ListRequestLimitMax), int32(cfg.ListRequestLimitDefault))

				managersMap := make(map[string]any)
				ksvc.keyManagerFactories = make([]registeredManagers, 0, len(srp.KeyManagerCtxFactories))
				for i, factory := range srp.KeyManagerCtxFactories {
					rm := registeredManagers{
						Name:        factory.Name,
						Description: "Key manager: " + factory.Name,
					}
					ksvc.keyManagerFactories = append(ksvc.keyManagerFactories, rm)
					managersMap[fmt.Sprintf("manager_%d", i)] = map[string]any{
						"name":        factory.Name,
						"description": "Key manager: " + factory.Name,
					}
				}

				if err := wellknownconfiguration.RegisterConfiguration("key_managers", managersMap); err != nil {
					srp.Logger.Warn("failed to register key managers in well-known configuration", slog.Any("error", err))
				}

				return ksvc, nil
			},
		},
	}
}

// Close gracefully shuts down the service, closing the database client.
func (ksvc *Service) Close() {
	ksvc.logger.Info("gracefully shutting down key management service")
	ksvc.dbClient.Close()
}

func (ksvc Service) CreateProviderConfig(ctx context.Context, req *keyMgmtProto.CreateProviderConfigRequest) (*keyMgmtProto.CreateProviderConfigResponse, error) {
	rsp := &keyMgmtProto.CreateProviderConfigResponse{}

	ksvc.logger.DebugContext(ctx, "creating Provider Config",
		slog.String("name", req.GetName()),
		slog.String("manager",
			req.GetManager()))

	// Validate that manager is provided and registered
	manager := req.GetManager()
	if manager == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, "manager field is required")
	}
	if !ksvc.isManagerRegistered(manager) {
		ksvc.logger.WarnContext(ctx, "create provider: manager type is not registered",
			slog.String("manager", manager),
			slog.Any("registered_managers", ksvc.listManagerNames()))
	}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeKeyManagementProviderConfig,
	}

	err := ksvc.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		pc, err := txClient.CreateProviderConfig(ctx, req)
		if err != nil {
			return err
		}

		auditParams.ObjectID = pc.GetId()
		auditParams.Original = &policy.KeyProviderConfig{
			Id:       pc.GetId(),
			Name:     pc.GetName(),
			Manager:  pc.GetManager(),
			Metadata: pc.GetMetadata(),
		}

		rsp.ProviderConfig = pc
		return nil
	})
	if err != nil {
		ksvc.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, ksvc.logger, err, db.ErrTextCreationFailed, slog.String("key_management_service", req.GetName()))
	}
	ksvc.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	return rsp, nil
}

func (ksvc Service) GetProviderConfig(ctx context.Context, req *keyMgmtProto.GetProviderConfigRequest) (*keyMgmtProto.GetProviderConfigResponse, error) {
	rsp := &keyMgmtProto.GetProviderConfigResponse{}

	ksvc.logger.DebugContext(ctx, "getting Provider Config")

	pc, err := ksvc.dbClient.GetProviderConfig(ctx, req)
	if err != nil {
		return nil, db.StatusifyError(ctx, ksvc.logger, err, db.ErrTextGetRetrievalFailed, slog.String("key_management_service", req.String()))
	}

	rsp.ProviderConfig = pc
	return rsp, nil
}

func (ksvc Service) ListProviderConfigs(ctx context.Context, req *keyMgmtProto.ListProviderConfigsRequest) (*keyMgmtProto.ListProviderConfigsResponse, error) {
	ksvc.logger.DebugContext(ctx, "listing Provider Configs")

	resp, err := ksvc.dbClient.ListProviderConfigs(ctx, req.GetPagination())
	if err != nil {
		return nil, db.StatusifyError(ctx, ksvc.logger, err, db.ErrTextGetRetrievalFailed, slog.String("key_management_service", req.String()))
	}

	return resp, nil
}

func (ksvc Service) UpdateProviderConfig(ctx context.Context, req *keyMgmtProto.UpdateProviderConfigRequest) (*keyMgmtProto.UpdateProviderConfigResponse, error) {
	rsp := &keyMgmtProto.UpdateProviderConfigResponse{}
	providerConfigID := req.GetId()

	ksvc.logger.DebugContext(ctx, "updating Provider Config", slog.String("id", req.GetId()))

	// Validate manager type if provided
	manager := req.GetManager()
	if manager != "" && !ksvc.isManagerRegistered(manager) {
		ksvc.logger.WarnContext(ctx, "update provider: manager type is not registered", slog.String("manager", manager))
	}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeKeyManagementProviderConfig,
		ObjectID:   providerConfigID,
	}

	original, err := ksvc.dbClient.GetProviderConfig(ctx, &keyMgmtProto.GetProviderConfigRequest{
		Identifier: &keyMgmtProto.GetProviderConfigRequest_Id{
			Id: providerConfigID,
		},
	})
	if err != nil {
		ksvc.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, ksvc.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", providerConfigID))
	}

	err = ksvc.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		pc, err := txClient.UpdateProviderConfig(ctx, req)
		if err != nil {
			return err
		}

		// Lets not log the full provider config, leave off config json
		// in case it contains sensitive information
		auditParams.Original = &policy.KeyProviderConfig{
			Id:       original.GetId(),
			Name:     original.GetName(),
			Manager:  original.GetManager(),
			Metadata: original.GetMetadata(),
		}
		auditParams.Updated = &policy.KeyProviderConfig{
			Id:       pc.GetId(),
			Name:     pc.GetName(),
			Manager:  pc.GetManager(),
			Metadata: pc.GetMetadata(),
		}
		rsp.ProviderConfig = pc

		return nil
	})
	if err != nil {
		ksvc.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, ksvc.logger, err, db.ErrTextUpdateFailed, slog.String("key_management_service", req.GetId()))
	}
	ksvc.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	return rsp, nil
}

func (ksvc Service) DeleteProviderConfig(ctx context.Context, req *keyMgmtProto.DeleteProviderConfigRequest) (*keyMgmtProto.DeleteProviderConfigResponse, error) {
	rsp := &keyMgmtProto.DeleteProviderConfigResponse{}

	ksvc.logger.DebugContext(ctx, "deleting Provider Config", slog.String("id", req.GetId()))

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeKeyManagementProviderConfig,
	}

	pc, err := ksvc.dbClient.DeleteProviderConfig(ctx, req.GetId())
	if err != nil {
		ksvc.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, ksvc.logger, err, db.ErrTextDeletionFailed, slog.String("key_management_service", req.GetId()))
	}

	auditParams.ObjectID = pc.GetId()
	auditParams.Original = &policy.KeyProviderConfig{
		Id:       pc.GetId(),
		Name:     pc.GetName(),
		Manager:  pc.GetManager(),
		Metadata: pc.GetMetadata(),
	}
	ksvc.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	rsp.ProviderConfig = pc

	return rsp, nil
}

// isManagerRegistered checks if a manager name is available in the trust key manager factories
func (ksvc *Service) isManagerRegistered(managerName string) bool {
	for _, factory := range ksvc.keyManagerFactories {
		if factory.Name == managerName {
			return true
		}
	}
	return false
}

func (ksvc Service) listManagerNames() []string {
	names := make([]string, 0, len(ksvc.keyManagerFactories))
	for _, factory := range ksvc.keyManagerFactories {
		names = append(names, factory.Name)
	}
	return names
}
