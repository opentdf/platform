package kasregistry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy"
	kasr "github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry/kasregistryconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policyconfig "github.com/opentdf/platform/service/policy/config"

	policydb "github.com/opentdf/platform/service/policy/db"
)

var (
	ErrFailedToDecodePEM      = errors.New("failed to decode PEM block from public key")
	ErrFailedToParsePublicKey = errors.New("failed to parse public key from PEM block")
	ErrUnsupportedKeyAlg      = errors.New("unsupported key algorithm")
	ErrKeyAlgMismatch         = errors.New("key algorithm does not match the provided algorithm")
	ErrInvalidRSAKeySize      = errors.New("invalid rsa key size")
	ErrInvalidECKeyCurve      = errors.New("invalid ec key curve")
	ErrUnsupportedCurve       = errors.New("unsupported curve")
)

type KeyAccessServerRegistry struct {
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
	config   *policyconfig.Config
}

func OnConfigUpdate(kasrSvc *KeyAccessServerRegistry) serviceregistry.OnConfigUpdateHook {
	return func(_ context.Context, cfg config.ServiceConfig) error {
		sharedCfg, err := policyconfig.GetSharedPolicyConfig(cfg)
		if err != nil {
			return fmt.Errorf("failed to get shared policy config: %w", err)
		}
		kasrSvc.config = sharedCfg
		kasrSvc.dbClient = policydb.NewClient(kasrSvc.dbClient.Client, kasrSvc.logger, int32(sharedCfg.ListRequestLimitMax), int32(sharedCfg.ListRequestLimitDefault))

		kasrSvc.logger.Info("key access server registry service config reloaded")

		return nil
	}
}

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[kasregistryconnect.KeyAccessServerRegistryServiceHandler] {
	kasrSvc := new(KeyAccessServerRegistry)
	onUpdateConfigHook := OnConfigUpdate(kasrSvc)
	return &serviceregistry.Service[kasregistryconnect.KeyAccessServerRegistryServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[kasregistryconnect.KeyAccessServerRegistryServiceHandler]{
			Namespace:       ns,
			DB:              dbRegister,
			ServiceDesc:     &kasr.KeyAccessServerRegistryService_ServiceDesc,
			ConnectRPCFunc:  kasregistryconnect.NewKeyAccessServerRegistryServiceHandler,
			GRPCGatewayFunc: kasr.RegisterKeyAccessServerRegistryServiceHandler,
			OnConfigUpdate:  onUpdateConfigHook,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (kasregistryconnect.KeyAccessServerRegistryServiceHandler, serviceregistry.HandlerServer) {
				logger := srp.Logger
				cfg, err := policyconfig.GetSharedPolicyConfig(srp.Config)
				if err != nil {
					logger.Error("error getting keyaccessserverregistry service policy config", slog.String("error", err.Error()))
					panic(err)
				}

				kasrSvc.logger = logger
				kasrSvc.dbClient = policydb.NewClient(srp.DBClient, logger, int32(cfg.ListRequestLimitMax), int32(cfg.ListRequestLimitDefault))
				kasrSvc.config = cfg
				return kasrSvc, nil
			},
		},
	}
}

func (s KeyAccessServerRegistry) CreateKeyAccessServer(ctx context.Context,
	req *connect.Request[kasr.CreateKeyAccessServerRequest],
) (*connect.Response[kasr.CreateKeyAccessServerResponse], error) {
	rsp := &kasr.CreateKeyAccessServerResponse{}

	s.logger.Debug("creating key access server")

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeKasRegistry,
	}

	ks, err := s.dbClient.CreateKeyAccessServer(ctx, req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("keyAccessServer", req.Msg.String()))
	}

	auditParams.ObjectID = ks.GetId()
	auditParams.Original = ks
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.KeyAccessServer = ks

	return connect.NewResponse(rsp), nil
}

func (s KeyAccessServerRegistry) ListKeyAccessServers(ctx context.Context,
	req *connect.Request[kasr.ListKeyAccessServersRequest],
) (*connect.Response[kasr.ListKeyAccessServersResponse], error) {
	rsp, err := s.dbClient.ListKeyAccessServers(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	return connect.NewResponse(rsp), nil
}

func (s KeyAccessServerRegistry) GetKeyAccessServer(ctx context.Context,
	req *connect.Request[kasr.GetKeyAccessServerRequest],
) (*connect.Response[kasr.GetKeyAccessServerResponse], error) {
	rsp := &kasr.GetKeyAccessServerResponse{}

	var identifier any

	if req.Msg.GetId() != "" { //nolint:staticcheck // Id can still be used until removed
		identifier = req.Msg.GetId() //nolint:staticcheck // Id can still be used until removed
	} else {
		identifier = req.Msg.GetIdentifier()
	}

	keyAccessServer, err := s.dbClient.GetKeyAccessServer(ctx, identifier)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.Any("id", identifier))
	}

	rsp.KeyAccessServer = keyAccessServer

	return connect.NewResponse(rsp), nil
}

func (s KeyAccessServerRegistry) UpdateKeyAccessServer(ctx context.Context,
	req *connect.Request[kasr.UpdateKeyAccessServerRequest],
) (*connect.Response[kasr.UpdateKeyAccessServerResponse], error) {
	rsp := &kasr.UpdateKeyAccessServerResponse{}

	kasID := req.Msg.GetId()

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeKasRegistry,
		ObjectID:   kasID,
	}

	original, err := s.dbClient.GetKeyAccessServer(ctx, kasID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", kasID))
	}

	updated, err := s.dbClient.UpdateKeyAccessServer(ctx, kasID, req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", kasID), slog.String("keyAccessServer", req.Msg.String()))
	}

	auditParams.Original = original
	auditParams.Updated = updated
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.KeyAccessServer = &policy.KeyAccessServer{
		Id: kasID,
	}

	return connect.NewResponse(rsp), nil
}

func (s KeyAccessServerRegistry) DeleteKeyAccessServer(ctx context.Context,
	req *connect.Request[kasr.DeleteKeyAccessServerRequest],
) (*connect.Response[kasr.DeleteKeyAccessServerResponse], error) {
	rsp := &kasr.DeleteKeyAccessServerResponse{}

	kasID := req.Msg.GetId()
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeKasRegistry,
		ObjectID:   kasID,
	}

	_, err := s.dbClient.DeleteKeyAccessServer(ctx, req.Msg.GetId())
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", req.Msg.GetId()))
	}
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.KeyAccessServer = &policy.KeyAccessServer{
		Id: kasID,
	}

	return connect.NewResponse(rsp), nil
}

func (s KeyAccessServerRegistry) ListKeyAccessServerGrants(ctx context.Context,
	req *connect.Request[kasr.ListKeyAccessServerGrantsRequest],
) (*connect.Response[kasr.ListKeyAccessServerGrantsResponse], error) {
	rsp, err := s.dbClient.ListKeyAccessServerGrants(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	return connect.NewResponse(rsp), nil
}

func (s KeyAccessServerRegistry) CreateKey(context.Context, *connect.Request[kasr.CreateKeyRequest]) (*connect.Response[kasr.CreateKeyResponse], error) {
	// Implementation for CreateKey
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

func (s KeyAccessServerRegistry) UpdateKey(context.Context, *connect.Request[kasr.UpdateKeyRequest]) (*connect.Response[kasr.UpdateKeyResponse], error) {
	// Implementation for UpdateKey
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

func (s KeyAccessServerRegistry) GetKey(context.Context, *connect.Request[kasr.GetKeyRequest]) (*connect.Response[kasr.GetKeyResponse], error) {
	// Implementation for GetKey
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

func (s KeyAccessServerRegistry) ListKeys(context.Context, *connect.Request[kasr.ListKeysRequest]) (*connect.Response[kasr.ListKeysResponse], error) {
	// Implementation for ListKeys
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

func (s KeyAccessServerRegistry) RotateKey(context.Context, *connect.Request[kasr.RotateKeyRequest]) (*connect.Response[kasr.RotateKeyResponse], error) {
	// Implementation for RotateKey
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}
