package keymanagement

import (
	"context"
	"log/slog"

	"connectrpc.com/connect"
	keyMgmtProto "github.com/opentdf/platform/protocol/go/policy/keymanagement"
	keyMgmtConnect "github.com/opentdf/platform/protocol/go/policy/keymanagement/keymanagementconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
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

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[keyMgmtConnect.KeyManagementServiceHandler] {
	return &serviceregistry.Service[keyMgmtConnect.KeyManagementServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[keyMgmtConnect.KeyManagementServiceHandler]{
			Namespace:      ns,
			DB:             dbRegister,
			ServiceDesc:    &keyMgmtProto.KeyManagementService_ServiceDesc,
			ConnectRPCFunc: keyMgmtConnect.NewKeyManagementServiceHandler,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (keyMgmtConnect.KeyManagementServiceHandler, serviceregistry.HandlerServer) {
				cfg := policyconfig.GetSharedPolicyConfig(srp)
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

	pc, err := ksvc.dbClient.CreateProviderConfig(ctx, req.Msg)
	if err != nil {
		ksvc.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("keyManagementService", req.Msg.GetName()))
	}

	auditParams.ObjectID = pc.GetId()
	auditParams.Original = pc
	ksvc.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.ProviderConfig = pc

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

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeKeyManagementProviderConfig,
	}

	pc, err := ksvc.dbClient.GetProviderConfig(ctx, req.Msg.GetIdentifier())
	if err != nil {
		ksvc.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("keyManagementService", req.Msg.String()))
	}

	auditParams.ObjectID = pc.GetId()
	auditParams.Original = pc
	ksvc.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

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
	providerConfigId := req.Msg.GetId()

	ksvc.logger.Debug("Updating Provider Config", slog.String("id", req.Msg.GetId()))

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeKeyManagementProviderConfig,
		ObjectID:   providerConfigId,
	}

	original, err := ksvc.dbClient.GetProviderConfig(ctx, &keyMgmtProto.GetProviderConfigRequest_Id{
		Id: providerConfigId,
	})
	if err != nil {
		ksvc.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", providerConfigId))
	}

	pc, err := ksvc.dbClient.UpdateProviderConfig(ctx, req.Msg)
	if err != nil {
		ksvc.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("keyManagementService", req.Msg.GetId()))
	}

	auditParams.Original = original
	auditParams.Updated = pc
	ksvc.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	rsp.ProviderConfig = pc

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
	auditParams.Original = pc
	ksvc.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.ProviderConfig = pc

	return connect.NewResponse(rsp), nil
}
