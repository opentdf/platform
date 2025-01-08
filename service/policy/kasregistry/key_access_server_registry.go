package kasregistry

import (
	"context"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy"
	kasr "github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry/kasregistryconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policyconfig "github.com/opentdf/platform/service/policy/config"

	policydb "github.com/opentdf/platform/service/policy/db"
)

type KeyAccessServerRegistry struct {
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
	config   *policyconfig.Config
}

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[kasregistryconnect.KeyAccessServerRegistryServiceHandler] {
	return &serviceregistry.Service[kasregistryconnect.KeyAccessServerRegistryServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[kasregistryconnect.KeyAccessServerRegistryServiceHandler]{
			Namespace:      ns,
			DB:             dbRegister,
			ServiceDesc:    &kasr.KeyAccessServerRegistryService_ServiceDesc,
			ConnectRPCFunc: kasregistryconnect.NewKeyAccessServerRegistryServiceHandler,
			GRPCGateayFunc: kasr.RegisterKeyAccessServerRegistryServiceHandlerFromEndpoint,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (kasregistryconnect.KeyAccessServerRegistryServiceHandler, serviceregistry.HandlerServer) {
				cfg := policyconfig.GetSharedPolicyConfig(srp)
				return &KeyAccessServerRegistry{
					dbClient: policydb.NewClient(srp.DBClient, srp.Logger, int32(cfg.ListRequestLimitMax), int32(cfg.ListRequestLimitDefault)),
					logger:   srp.Logger,
					config:   cfg,
				}, nil
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

	keyAccessServer, err := s.dbClient.GetKeyAccessServer(ctx, req.Msg.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.Msg.GetId()))
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

func (s KeyAccessServerRegistry) CreateKey(ctx context.Context, req *connect.Request[kasr.CreateKeyRequest]) (*connect.Response[kasr.CreateKeyResponse], error) {
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypePublicKey,
	}

	resp, err := s.dbClient.CreateKey(ctx, req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed)
	}

	auditParams.ObjectID = resp.GetKey().GetId()
	auditParams.Original = resp.GetKey()
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	return connect.NewResponse(resp), nil
}

func (s KeyAccessServerRegistry) GetKey(ctx context.Context, req *connect.Request[kasr.GetKeyRequest]) (*connect.Response[kasr.GetKeyResponse], error) {
	resp, err := s.dbClient.GetPublicKey(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed)
	}

	return connect.NewResponse(resp), nil
}

func (s KeyAccessServerRegistry) ListKeys(ctx context.Context, req *connect.Request[kasr.ListKeysRequest]) (*connect.Response[kasr.ListKeysResponse], error) {
	resp, err := s.dbClient.ListKeys(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}
	return connect.NewResponse(resp), nil
}

func (s KeyAccessServerRegistry) UpdateKey(ctx context.Context, req *connect.Request[kasr.UpdateKeyRequest]) (*connect.Response[kasr.UpdateKeyResponse], error) {
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypePublicKey,
		ObjectID:   req.Msg.GetId(),
	}

	original, err := s.dbClient.GetPublicKey(ctx, &kasr.GetKeyRequest{Id: req.Msg.GetId()})
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed)
	}

	resp, err := s.dbClient.UpdatePublicKey(ctx, req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed)
	}

	auditParams.Original = original
	auditParams.Updated = resp.GetKey()
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	return connect.NewResponse(resp), nil
}

func (s KeyAccessServerRegistry) DeleteKey(ctx context.Context, req *connect.Request[kasr.DeleteKeyRequest]) (*connect.Response[kasr.DeleteKeyResponse], error) {
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypePublicKey,
		ObjectID:   req.Msg.GetId(),
	}

	resp, err := s.dbClient.SoftDeleteKey(ctx, req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed)
	}
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	return connect.NewResponse(resp), nil
}
