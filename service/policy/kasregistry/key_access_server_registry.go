package kasregistry

import (
	"context"
	"errors"
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

func (s KeyAccessServerRegistry) CreateKey(ctx context.Context, r *connect.Request[kasr.CreateKeyRequest]) (*connect.Response[kasr.CreateKeyResponse], error) {
	s.logger.Debug("creating key", slog.String("keyAccessServer Keys", r.Msg.GetKasId()))

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeKasRegistryKeys,
	}

	resp, err := s.dbClient.CreateKey(ctx, r.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("keyAccessServer Keys", r.Msg.GetKasId()), slog.String("key id", r.Msg.GetKeyId()))
	}

	auditParams.ObjectID = resp.GetKey().GetKeyId()
	auditParams.Original = resp.GetKey() // should we be logging this it will have the wrapped KEK and pub key?
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	return connect.NewResponse(resp), nil
}

func (s KeyAccessServerRegistry) UpdateKey(ctx context.Context, req *connect.Request[kasr.UpdateKeyRequest]) (*connect.Response[kasr.UpdateKeyResponse], error) {
	rsp := &kasr.UpdateKeyResponse{}
	s.logger.Debug("updating key", slog.String("keyAccessServer Keys", req.Msg.GetId()))

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeKasRegistryKeys,
		ObjectID:   req.Msg.GetId(),
	}

	original, err := s.dbClient.GetKey(ctx, &kasr.GetKeyRequest_Id{
		Id: req.Msg.GetId(),
	})
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("keyAccessServer Keys", req.Msg.GetId()))
	}

	updated, err := s.dbClient.UpdateKey(ctx, req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("keyAccessServer Keys", req.Msg.GetId()))
	}

	auditParams.Original = original
	auditParams.Updated = updated
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.Key = updated

	return connect.NewResponse(rsp), nil
}

func (s KeyAccessServerRegistry) GetKey(ctx context.Context, r *connect.Request[kasr.GetKeyRequest]) (*connect.Response[kasr.GetKeyResponse], error) {
	rsp := &kasr.GetKeyResponse{}

	switch i := r.Msg.GetIdentifier().(type) {
	case *kasr.GetKeyRequest_Id:
		s.logger.Debug("Getting keyAccessServer key by ID", slog.String("ID", i.Id))
	case *kasr.GetKeyRequest_KeyId:
		s.logger.Debug("Getting keyAccessServer by KeyId", slog.String("Name", i.KeyId))
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, nil)
	}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeRead,
		ObjectType: audit.ObjectTypeKasRegistryKeys,
	}

	key, err := s.dbClient.GetKey(ctx, r.Msg.GetIdentifier())
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("keyAccessServer Keys", r.Msg.String()))
	}

	auditParams.ObjectID = key.GetKeyId()
	auditParams.Original = key
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.Key = key

	return connect.NewResponse(rsp), nil
}

func (s KeyAccessServerRegistry) ListKeys(ctx context.Context, r *connect.Request[kasr.ListKeysRequest]) (*connect.Response[kasr.ListKeysResponse], error) {
	s.logger.Debug("Listing KAS Keys")
	resp, err := s.dbClient.ListKeys(ctx, r.Msg)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed, slog.String("keyAccessServer Keys", r.Msg.String()))
	}

	return connect.NewResponse(resp), nil
}

func (s KeyAccessServerRegistry) RotateKey(context.Context, *connect.Request[kasr.RotateKeyRequest]) (*connect.Response[kasr.RotateKeyResponse], error) {
	// Implementation for RotateKey
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}
