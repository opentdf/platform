package keymanagement

import (
	"context"

	"connectrpc.com/connect"
	keyMgmtProto "github.com/opentdf/platform/protocol/go/policy/keymanagement"
	keyMgmtConnect "github.com/opentdf/platform/protocol/go/policy/keymanagement/keymanagementconnect"
	"github.com/opentdf/platform/service/logger"
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

func (ksvc Service) CreateProviderConfig(context.Context, *connect.Request[keyMgmtProto.CreateProviderConfigRequest]) (*connect.Response[keyMgmtProto.CreateProviderConfigResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}
func (ksvc Service) GetProviderConfig(context.Context, *connect.Request[keyMgmtProto.GetProviderConfigRequest]) (*connect.Response[keyMgmtProto.GetProviderConfigResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}
func (ksvc Service) ListProviderConfigs(context.Context, *connect.Request[keyMgmtProto.ListProviderConfigsRequest]) (*connect.Response[keyMgmtProto.ListProviderConfigsResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}
func (ksvc Service) UpdateProviderConfig(context.Context, *connect.Request[keyMgmtProto.UpdateProviderConfigRequest]) (*connect.Response[keyMgmtProto.UpdateProviderConfigResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}
func (ksvc Service) DeleteProviderConfig(context.Context, *connect.Request[keyMgmtProto.DeleteProviderConfigRequest]) (*connect.Response[keyMgmtProto.DeleteProviderConfigResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}
