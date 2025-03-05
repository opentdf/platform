package keymanagement

import (
	"context"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy/keymanagement"
	"github.com/opentdf/platform/protocol/go/policy/keymanagement/keymanagementconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type KeyManagementService struct {
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
	config   *policyconfig.Config
}

func NewRegistration(ns string) *serviceregistry.Service[keymanagementconnect.KeyManagementServiceHandler] {
	return &serviceregistry.Service[keymanagementconnect.KeyManagementServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[keymanagementconnect.KeyManagementServiceHandler]{
			Namespace:      ns,
			ServiceDesc:    &keymanagement.KeyManagementService_ServiceDesc,
			ConnectRPCFunc: keymanagementconnect.NewKeyManagementServiceHandler,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (keymanagementconnect.KeyManagementServiceHandler, serviceregistry.HandlerServer) {
				cfg := policyconfig.GetSharedPolicyConfig(srp)
				p := &KeyManagementService{
					dbClient: policydb.NewClient(srp.DBClient, srp.Logger, int32(cfg.ListRequestLimitMax), int32(cfg.ListRequestLimitDefault)),
					logger:   srp.Logger,
				}

				if err := srp.RegisterReadinessCheck("keymanagement", p.IsReady); err != nil {
					srp.Logger.Error("failed to register keymanagement readiness check", logger.Error(err))
				}

				return p, nil
			},
		},
	}
}

func (kmsvc KeyManagementService) CreateKeyAccessServer(ctx context.Context, req *connect.Request[keymanagementconnect.CreateKeyAccessServerRequest]) (*connect.Response[keymanagement.CreateKeyAccessServerResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}

func (kmsvc KeyManagementService) GetKeyAccessServer(ctx context.Context, req *connect.Request[keymanagement.GetKeyAccessServerRequest]) (*connect.Response[keymanagement.GetKeyAccessServerResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}
func (kmsvc KeyManagementService) ListKeyAccessServers(ctx context.Context, req *connect.Request[keymanagement.ListKeyAccessServersRequest]) (*connect.Response[keymanagement.ListKeyAccessServersResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}
func (kmsvc KeyManagementService) UpdateKeyAccessServer(ctx context.Context, req *connect.Request[keymanagement.UpdateKeyAccessServerRequest]) (*connect.Response[keymanagement.UpdateKeyAccessServerResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}

// Key Management
func (kmsvc KeyManagementService) CreateKey(ctx context.Context, req *connect.Request[keymanagement.CreateKeyRequest]) (*connect.Response[keymanagement.CreateKeyResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}
func (kmsvc KeyManagementService) GetKey(ctx context.Context, req *connect.Request[keymanagement.GetKeyRequest]) (*connect.Response[keymanagement.GetKeyResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}
func (kmsvc KeyManagementService) ListKeys(ctx context.Context, req *connect.Request[keymanagement.ListKeysRequest]) (*connect.Response[keymanagement.ListKeysResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}
func (kmsvc KeyManagementService) UpdateKey(ctx context.Context, req *connect.Request[keymanagement.UpdateKeyRequest]) (*connect.Response[keymanagement.UpdateKeyResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}
func (kmsvc KeyManagementService) RotateKey(ctx context.Context, req *connect.Request[keymanagement.RotateKeyRequest]) (*connect.Response[keymanagement.RotateKeyResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}
