package kasregistry

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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
	ErrInvalidKeyAlg    = errors.New("invalid key algorithm")
	ErrInvalidKey       = errors.New("invalid key")
	ErrInvalidKeySize   = errors.New("invalid key size")
	ErrInvalidKeyCurve  = errors.New("invalid key curve")
	ErrUnsupportedCurve = errors.New("unsupported curve")
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

func (s KeyAccessServerRegistry) CreatePublicKey(ctx context.Context, req *connect.Request[kasr.CreatePublicKeyRequest]) (*connect.Response[kasr.CreatePublicKeyResponse], error) {
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypePublicKey,
	}

	// Verify the key matches the algorithm
	if err := verifyKeyAlg(req.Msg.GetKey().GetPem(), req.Msg.GetKey().GetAlg()); err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	resp, err := s.dbClient.CreatePublicKey(ctx, req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		s.logger.ErrorContext(ctx, "failed to create key", slog.Any("key", err.Error()))
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed)
	}

	auditParams.ObjectID = resp.GetKey().GetId()
	auditParams.Original = resp.GetKey()
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	return connect.NewResponse(resp), nil
}

// Helper function to get curve from algorithm
func getCurveFromAlg(alg policy.KasPublicKeyAlgEnum) (elliptic.Curve, error) {
	switch alg { //nolint:exhaustive // covers ec cases
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1:
		return elliptic.P256(), nil
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP384R1:
		return elliptic.P384(), nil
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP521R1:
		return elliptic.P521(), nil
	default:
		return nil, ErrUnsupportedCurve
	}
}

// Verify the key matches the algorithm
func verifyKeyAlg(key string, alg policy.KasPublicKeyAlgEnum) error {
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return ErrInvalidKey
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return ErrInvalidKey
	}

	switch alg { //nolint:exhaustive // covers all cases
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048,
		policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_4096:

		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return ErrInvalidKeyAlg
		}

		expectedSize := 0
		switch alg { //nolint:exhaustive // only covers rsa
		case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048:
			expectedSize = 256 // 2048 bits
		case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_4096:
			expectedSize = 512 // 4096 bits
		}

		if rsaKey.Size() != expectedSize { // 2048 bits = 256 bytes
			return ErrInvalidKeySize
		}
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1,
		policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP384R1,
		policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP521R1:

		ecKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return ErrInvalidKeyAlg
		}

		expectedCurve, err := getCurveFromAlg(alg)
		if err != nil {
			return err
		}

		if ecKey.Curve != expectedCurve {
			return ErrInvalidKeyCurve
		}
	default:
		return ErrInvalidKeyAlg
	}
	return nil
}

func (s KeyAccessServerRegistry) GetPublicKey(ctx context.Context, req *connect.Request[kasr.GetPublicKeyRequest]) (*connect.Response[kasr.GetPublicKeyResponse], error) {
	resp, err := s.dbClient.GetPublicKey(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed)
	}

	return connect.NewResponse(resp), nil
}

func (s KeyAccessServerRegistry) ListPublicKeys(ctx context.Context, req *connect.Request[kasr.ListPublicKeysRequest]) (*connect.Response[kasr.ListPublicKeysResponse], error) {
	resp, err := s.dbClient.ListPublicKeys(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}
	return connect.NewResponse(resp), nil
}

func (s KeyAccessServerRegistry) ListPublicKeyMapping(ctx context.Context, req *connect.Request[kasr.ListPublicKeyMappingRequest]) (*connect.Response[kasr.ListPublicKeyMappingResponse], error) {
	resp, err := s.dbClient.ListPublicKeyMappings(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}
	return connect.NewResponse(resp), nil
}

func (s KeyAccessServerRegistry) UpdatePublicKey(ctx context.Context, req *connect.Request[kasr.UpdatePublicKeyRequest]) (*connect.Response[kasr.UpdatePublicKeyResponse], error) {
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypePublicKey,
		ObjectID:   req.Msg.GetId(),
	}

	original, err := s.dbClient.GetPublicKey(ctx, &kasr.GetPublicKeyRequest{Id: req.Msg.GetId()})
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

func (s KeyAccessServerRegistry) DeactivatePublicKey(ctx context.Context, req *connect.Request[kasr.DeactivatePublicKeyRequest]) (*connect.Response[kasr.DeactivatePublicKeyResponse], error) {
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypePublicKey,
		ObjectID:   req.Msg.GetId(),
	}

	resp, err := s.dbClient.DeactivatePublicKey(ctx, req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed)
	}
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	return connect.NewResponse(resp), nil
}

func (s KeyAccessServerRegistry) ActivatePublicKey(ctx context.Context, req *connect.Request[kasr.ActivatePublicKeyRequest]) (*connect.Response[kasr.ActivatePublicKeyResponse], error) {
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypePublicKey,
		ObjectID:   req.Msg.GetId(),
	}

	resp, err := s.dbClient.ActivatePublicKey(ctx, req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed)
	}
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	return connect.NewResponse(resp), nil
}
