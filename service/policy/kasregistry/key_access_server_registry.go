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
	"github.com/opentdf/platform/service/internal/auth/authz"
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

const (
	authzDimKASID   = "kas_id"
	authzDimKASName = "kas_name"
	authzDimKASURI  = "kas_uri"
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
		Close: kasrSvc.Close,
		ServiceOptions: serviceregistry.ServiceOptions[kasregistryconnect.KeyAccessServerRegistryServiceHandler]{
			Namespace:      ns,
			DB:             dbRegister,
			ServiceDesc:    &kasr.KeyAccessServerRegistryService_ServiceDesc,
			ConnectRPCFunc: kasregistryconnect.NewKeyAccessServerRegistryServiceHandler,
			OnConfigUpdate: onUpdateConfigHook,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (kasregistryconnect.KeyAccessServerRegistryServiceHandler, serviceregistry.HandlerServer) {
				logger := srp.Logger
				cfg, err := policyconfig.GetSharedPolicyConfig(srp.Config)
				if err != nil {
					logger.Error("error getting keyaccessserverregistry service policy config", slog.String("error", err.Error()))
					panic(err)
				}

				kasrSvc.logger = logger
				kasrSvc.dbClient = policydb.NewClient(srp.DBClient, logger, int32(cfg.ListRequestLimitMax), int32(cfg.ListRequestLimitDefault))
				if err = kasrSvc.dbClient.SetBaseKeyOnWellKnownConfig(context.TODO()); err != nil {
					logger.Error("error setting well-known config", slog.String("error", err.Error()))
					panic(err)
				}

				kasrSvc.config = cfg
				kasrSvc.registerAuthzResolvers(srp.AuthzResolverRegistry)
				return kasrSvc, nil
			},
		},
	}
}

func (s *KeyAccessServerRegistry) registerAuthzResolvers(registry *authz.ScopedResolverRegistry) {
	if registry == nil {
		return
	}

	registry.MustRegister("GetKeyAccessServer", s.getKeyAccessServerAuthzResolver)
	registry.MustRegister("CreateKey", s.createKeyAuthzResolver)
	registry.MustRegister("GetKey", s.getKeyAuthzResolver)
	registry.MustRegister("ListKeys", s.listKeysAuthzResolver)
	registry.MustRegister("UpdateKey", s.updateKeyAuthzResolver)
	registry.MustRegister("RotateKey", s.rotateKeyAuthzResolver)
	registry.MustRegister("SetBaseKey", s.setBaseKeyAuthzResolver)
	registry.MustRegister("ListKeyMappings", s.listKeyMappingsAuthzResolver)
}

// Close gracefully shuts down the service, closing the database client.
func (s *KeyAccessServerRegistry) Close() {
	s.logger.Info("gracefully shutting down key access server registry service")
	s.dbClient.Close()
}

func (s KeyAccessServerRegistry) getKeyAccessServerAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	resolverCtx := authz.NewResolverContext()
	msg, ok := req.Any().(*kasr.GetKeyAccessServerRequest)
	if !ok {
		return resolverCtx, fmt.Errorf("unexpected request type: %T", req.Any())
	}

	res := resolverCtx.NewResource()
	if msg.GetId() != "" { //nolint:staticcheck // Id can still be used until removed
		if err := s.addResolvedKASDimensions(ctx, res, msg.GetId()); err != nil { //nolint:staticcheck // Id can still be used until removed
			return resolverCtx, err
		}
		return resolverCtx, nil
	}

	if err := s.addResolvedKASDimensions(ctx, res, msg.GetIdentifier()); err != nil {
		return resolverCtx, err
	}

	return resolverCtx, nil
}

func (s KeyAccessServerRegistry) createKeyAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	resolverCtx := authz.NewResolverContext()
	msg, ok := req.Any().(*kasr.CreateKeyRequest)
	if !ok {
		return resolverCtx, fmt.Errorf("unexpected request type: %T", req.Any())
	}

	res := resolverCtx.NewResource()
	if err := s.addResolvedKASDimensions(ctx, res, &kasr.GetKeyAccessServerRequest_KasId{KasId: msg.GetKasId()}); err != nil {
		return resolverCtx, err
	}

	return resolverCtx, nil
}

func (s KeyAccessServerRegistry) getKeyAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	resolverCtx := authz.NewResolverContext()
	msg, ok := req.Any().(*kasr.GetKeyRequest)
	if !ok {
		return resolverCtx, fmt.Errorf("unexpected request type: %T", req.Any())
	}

	res := resolverCtx.NewResource()
	if err := s.addKeyRequestDimensions(ctx, res, msg.GetIdentifier()); err != nil {
		return resolverCtx, err
	}

	return resolverCtx, nil
}

func (s KeyAccessServerRegistry) listKeysAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	resolverCtx := authz.NewResolverContext()
	msg, ok := req.Any().(*kasr.ListKeysRequest)
	if !ok {
		return resolverCtx, fmt.Errorf("unexpected request type: %T", req.Any())
	}

	res := resolverCtx.NewResource()
	if err := s.addListKeysFilterDimensions(ctx, res, msg.GetKasFilter()); err != nil {
		return resolverCtx, err
	}

	return resolverCtx, nil
}

func (s KeyAccessServerRegistry) updateKeyAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	resolverCtx := authz.NewResolverContext()
	msg, ok := req.Any().(*kasr.UpdateKeyRequest)
	if !ok {
		return resolverCtx, fmt.Errorf("unexpected request type: %T", req.Any())
	}

	res := resolverCtx.NewResource()
	if err := s.addKeyDimensionsByID(ctx, res, msg.GetId()); err != nil {
		return resolverCtx, err
	}

	return resolverCtx, nil
}

func (s KeyAccessServerRegistry) rotateKeyAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	resolverCtx := authz.NewResolverContext()
	msg, ok := req.Any().(*kasr.RotateKeyRequest)
	if !ok {
		return resolverCtx, fmt.Errorf("unexpected request type: %T", req.Any())
	}

	res := resolverCtx.NewResource()
	switch active := msg.GetActiveKey().(type) {
	case *kasr.RotateKeyRequest_Id:
		if err := s.addKeyDimensionsByID(ctx, res, active.Id); err != nil {
			return resolverCtx, err
		}
	case *kasr.RotateKeyRequest_Key:
		if err := s.addKASKeyIdentifierDimensions(ctx, res, active.Key); err != nil {
			return resolverCtx, err
		}
	default:
		return resolverCtx, errors.New("no active key identifier provided")
	}

	return resolverCtx, nil
}

func (s KeyAccessServerRegistry) setBaseKeyAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	resolverCtx := authz.NewResolverContext()
	msg, ok := req.Any().(*kasr.SetBaseKeyRequest)
	if !ok {
		return resolverCtx, fmt.Errorf("unexpected request type: %T", req.Any())
	}

	res := resolverCtx.NewResource()
	switch active := msg.GetActiveKey().(type) {
	case *kasr.SetBaseKeyRequest_Id:
		if err := s.addKeyDimensionsByID(ctx, res, active.Id); err != nil {
			return resolverCtx, err
		}
	case *kasr.SetBaseKeyRequest_Key:
		if err := s.addKASKeyIdentifierDimensions(ctx, res, active.Key); err != nil {
			return resolverCtx, err
		}
	default:
		return resolverCtx, errors.New("no active key identifier provided")
	}

	return resolverCtx, nil
}

func (s KeyAccessServerRegistry) listKeyMappingsAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	resolverCtx := authz.NewResolverContext()
	msg, ok := req.Any().(*kasr.ListKeyMappingsRequest)
	if !ok {
		return resolverCtx, fmt.Errorf("unexpected request type: %T", req.Any())
	}

	res := resolverCtx.NewResource()
	switch identifier := msg.GetIdentifier().(type) {
	case *kasr.ListKeyMappingsRequest_Id:
		if err := s.addKeyDimensionsByID(ctx, res, identifier.Id); err != nil {
			return resolverCtx, err
		}
	case *kasr.ListKeyMappingsRequest_Key:
		if err := s.addKASKeyIdentifierDimensions(ctx, res, identifier.Key); err != nil {
			return resolverCtx, err
		}
	case nil:
		// No dimensions means only wildcard-dimension policy can list all mappings.
	default:
		return resolverCtx, fmt.Errorf("unexpected key mapping identifier type: %T", identifier)
	}

	return resolverCtx, nil
}

func (s KeyAccessServerRegistry) addKeyRequestDimensions(ctx context.Context, res *authz.ResolverResource, identifier any) error {
	switch keyIdentifier := identifier.(type) {
	case *kasr.GetKeyRequest_Id:
		return s.addKeyDimensionsByID(ctx, res, keyIdentifier.Id)
	case *kasr.GetKeyRequest_Key:
		return s.addKASKeyIdentifierDimensions(ctx, res, keyIdentifier.Key)
	default:
		return fmt.Errorf("unexpected key identifier type: %T", identifier)
	}
}

func (s KeyAccessServerRegistry) addKeyDimensionsByID(ctx context.Context, res *authz.ResolverResource, id string) error {
	key, err := s.dbClient.GetKey(ctx, &kasr.GetKeyRequest_Id{Id: id})
	if err != nil {
		return fmt.Errorf("failed to resolve key for authz: %w", err)
	}
	addKASKeyDimensions(res, key)
	return nil
}

func (s KeyAccessServerRegistry) addKASKeyIdentifierDimensions(ctx context.Context, res *authz.ResolverResource, identifier *kasr.KasKeyIdentifier) error {
	if identifier == nil {
		return errors.New("key identifier is required")
	}

	switch kasIdentifier := identifier.GetIdentifier().(type) {
	case *kasr.KasKeyIdentifier_KasId:
		return s.addResolvedKASDimensions(ctx, res, &kasr.GetKeyAccessServerRequest_KasId{KasId: kasIdentifier.KasId})
	case *kasr.KasKeyIdentifier_Name:
		return s.addResolvedKASDimensions(ctx, res, &kasr.GetKeyAccessServerRequest_Name{Name: kasIdentifier.Name})
	case *kasr.KasKeyIdentifier_Uri:
		return s.addResolvedKASDimensions(ctx, res, &kasr.GetKeyAccessServerRequest_Uri{Uri: kasIdentifier.Uri})
	default:
		return fmt.Errorf("unexpected KAS identifier type: %T", kasIdentifier)
	}
}

func (s KeyAccessServerRegistry) addListKeysFilterDimensions(ctx context.Context, res *authz.ResolverResource, filter any) error {
	switch kasFilter := filter.(type) {
	case *kasr.ListKeysRequest_KasId:
		return s.addResolvedKASDimensions(ctx, res, &kasr.GetKeyAccessServerRequest_KasId{KasId: kasFilter.KasId})
	case *kasr.ListKeysRequest_KasName:
		return s.addResolvedKASDimensions(ctx, res, &kasr.GetKeyAccessServerRequest_Name{Name: kasFilter.KasName})
	case *kasr.ListKeysRequest_KasUri:
		return s.addResolvedKASDimensions(ctx, res, &kasr.GetKeyAccessServerRequest_Uri{Uri: kasFilter.KasUri})
	case nil:
		// No dimensions means only wildcard-dimension policy can list all keys.
		return nil
	default:
		return fmt.Errorf("unexpected KAS filter type: %T", kasFilter)
	}
}

func (s KeyAccessServerRegistry) addResolvedKASDimensions(ctx context.Context, res *authz.ResolverResource, identifier any) error {
	kas, err := s.dbClient.GetKeyAccessServer(ctx, identifier)
	if err != nil {
		return fmt.Errorf("failed to resolve KAS for authz: %w", err)
	}

	addKASDimensions(res, kas.GetId(), kas.GetName(), kas.GetUri())
	return nil
}

func addKASKeyDimensions(res *authz.ResolverResource, key *policy.KasKey) {
	if key == nil {
		return
	}
	addKASDimensions(res, key.GetKasId(), "", key.GetKasUri())
}

func addKASDimensions(res *authz.ResolverResource, id, name, uri string) {
	if id != "" {
		res.AddDimension(authzDimKASID, id)
	}
	if name != "" {
		res.AddDimension(authzDimKASName, name)
	}
	if uri != "" {
		res.AddDimension(authzDimKASURI, uri)
	}
}

func (s KeyAccessServerRegistry) CreateKeyAccessServer(ctx context.Context,
	req *connect.Request[kasr.CreateKeyAccessServerRequest],
) (*connect.Response[kasr.CreateKeyAccessServerResponse], error) {
	rsp := &kasr.CreateKeyAccessServerResponse{}

	s.logger.DebugContext(ctx, "creating key access server")

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeKasRegistry,
	}

	ks, err := s.dbClient.CreateKeyAccessServer(ctx, req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextCreationFailed, slog.String("key_access_server", req.Msg.String()))
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
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextListRetrievalFailed)
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
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.Any("id", identifier))
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
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", kasID))
	}

	updated, err := s.dbClient.UpdateKeyAccessServer(ctx, kasID, req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("id", kasID), slog.String("key_access_server", req.Msg.String()))
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
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeletionFailed, slog.String("id", req.Msg.GetId()))
	}
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.KeyAccessServer = &policy.KeyAccessServer{
		Id: kasID,
	}

	return connect.NewResponse(rsp), nil
}

func (s KeyAccessServerRegistry) ListKeyAccessServerGrants(ctx context.Context,
	req *connect.Request[kasr.ListKeyAccessServerGrantsRequest], //nolint:staticcheck // Compatibility path for deprecated RPC.
) (*connect.Response[kasr.ListKeyAccessServerGrantsResponse], error) { //nolint:staticcheck // Compatibility path for deprecated RPC.
	rsp, err := s.dbClient.ListKeyAccessServerGrants(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextListRetrievalFailed)
	}

	return connect.NewResponse(rsp), nil
}

func (s KeyAccessServerRegistry) CreateKey(ctx context.Context, r *connect.Request[kasr.CreateKeyRequest]) (*connect.Response[kasr.CreateKeyResponse], error) {
	s.logger.DebugContext(ctx, "creating key", slog.String("kas_keys", r.Msg.GetKasId()))

	resp := &kasr.CreateKeyResponse{}
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeKasRegistryKeys,
	}

	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		var err error
		resp, err = txClient.CreateKey(ctx, r.Msg)
		if err != nil {
			s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return err
		}

		auditParams.ObjectID = resp.GetKasKey().GetKey().GetId()
		// Leave off private key context and configjson from provider config
		// For security reasons
		auditParams.Original = &policy.KasKey{
			KasId: resp.GetKasKey().GetKasId(),
			Key: &policy.AsymmetricKey{
				KeyId:        resp.GetKasKey().GetKey().GetKeyId(),
				KeyAlgorithm: resp.GetKasKey().GetKey().GetKeyAlgorithm(),
				KeyStatus:    resp.GetKasKey().GetKey().GetKeyStatus(),
				KeyMode:      resp.GetKasKey().GetKey().GetKeyMode(),
				PublicKeyCtx: resp.GetKasKey().GetKey().GetPublicKeyCtx(),
				ProviderConfig: &policy.KeyProviderConfig{
					Id:       resp.GetKasKey().GetKey().GetProviderConfig().GetId(),
					Name:     resp.GetKasKey().GetKey().GetProviderConfig().GetName(),
					Metadata: resp.GetKasKey().GetKey().GetProviderConfig().GetMetadata(),
				},
				Metadata: resp.GetKasKey().GetKey().GetMetadata(),
			},
		}
		s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

		return nil
	})
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextCreationFailed, slog.String("key_access_server_keys", r.Msg.GetKasId()), slog.String("key_id", r.Msg.GetKeyId()))
	}

	return connect.NewResponse(resp), nil
}

func (s KeyAccessServerRegistry) UpdateKey(ctx context.Context, req *connect.Request[kasr.UpdateKeyRequest]) (*connect.Response[kasr.UpdateKeyResponse], error) {
	rsp := &kasr.UpdateKeyResponse{}
	s.logger.DebugContext(ctx, "updating key", slog.String("kas_keys", req.Msg.GetId()))

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
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("key_access_server_keys", req.Msg.GetId()))
	}

	err = s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		updated, err := txClient.UpdateKey(ctx, req.Msg)
		if err != nil {
			s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return err
		}

		// Only key status and metadata can be updated
		auditParams.Original = &policy.AsymmetricKey{
			KeyId:     original.GetKey().GetKeyId(),
			KeyStatus: original.GetKey().GetKeyStatus(),
			Metadata:  original.GetKey().GetMetadata(),
		}
		auditParams.Updated = &policy.AsymmetricKey{
			KeyId:     updated.GetKey().GetKeyId(),
			KeyStatus: updated.GetKey().GetKeyStatus(),
			Metadata:  updated.GetKey().GetMetadata(),
		}
		s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

		rsp.KasKey = updated
		return nil
	})
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("key_access_server_keys", req.Msg.GetId()))
	}

	return connect.NewResponse(rsp), nil
}

func (s KeyAccessServerRegistry) GetKey(ctx context.Context, r *connect.Request[kasr.GetKeyRequest]) (*connect.Response[kasr.GetKeyResponse], error) {
	rsp := &kasr.GetKeyResponse{}

	switch i := r.Msg.GetIdentifier().(type) {
	case *kasr.GetKeyRequest_Id:
		s.logger.DebugContext(ctx, "getting keyAccessServer key by ID", slog.String("id", i.Id))
	case *kasr.GetKeyRequest_Key:
		s.logger.DebugContext(ctx, "getting keyAccessServer by Key", slog.String("key_id", i.Key.GetKid()))
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
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("key_access_server_keys", r.Msg.String()))
	}

	auditParams.ObjectID = key.GetKey().GetKeyId()
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.KasKey = key

	return connect.NewResponse(rsp), nil
}

func (s KeyAccessServerRegistry) ListKeys(ctx context.Context, r *connect.Request[kasr.ListKeysRequest]) (*connect.Response[kasr.ListKeysResponse], error) {
	s.logger.DebugContext(ctx, "listing KAS Keys")
	resp, err := s.dbClient.ListKeys(ctx, r.Msg)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextListRetrievalFailed, slog.String("key_access_server_keys", r.Msg.String()))
	}

	return connect.NewResponse(resp), nil
}

func (s KeyAccessServerRegistry) RotateKey(ctx context.Context, r *connect.Request[kasr.RotateKeyRequest]) (*connect.Response[kasr.RotateKeyResponse], error) {
	var resp *kasr.RotateKeyResponse
	var objectID string
	var identifier any

	switch i := r.Msg.GetActiveKey().(type) {
	case *kasr.RotateKeyRequest_Id:
		s.logger.DebugContext(ctx, "rotating key by ID", slog.String("id", i.Id))
		objectID = i.Id
		identifier = &kasr.GetKeyRequest_Id{
			Id: i.Id,
		}
	case *kasr.RotateKeyRequest_Key:
		s.logger.DebugContext(ctx,
			"rotating key by Kas Key",
			slog.String("active_key_id", i.Key.GetKid()),
			slog.String("new_key_id", r.Msg.GetNewKey().GetKeyId()),
		)
		objectID = i.Key.GetKid()
		identifier = &kasr.GetKeyRequest_Key{
			Key: i.Key,
		}
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, nil)
	}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeRotate,
		ObjectType: audit.ObjectTypeKasRegistryKeys,
		ObjectID:   objectID,
	}

	original, err := s.dbClient.GetKey(ctx, identifier)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("key_access_server_keys", objectID))
	}

	auditParams.Original = &policy.KasKey{
		KasId: original.GetKasId(),
		Key: &policy.AsymmetricKey{
			KeyId:     original.GetKey().GetKeyId(),
			KeyStatus: original.GetKey().GetKeyStatus(),
		},
	}

	err = s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		resp, err = txClient.RotateKey(ctx, original, r.Msg.GetNewKey())
		if err != nil {
			s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return err
		}

		auditParams.Updated = &kasr.RotateKeyResponse{
			RotatedResources: &kasr.RotatedResources{
				RotatedOutKey: &policy.KasKey{
					KasId: resp.GetRotatedResources().GetRotatedOutKey().GetKasId(),
					Key: &policy.AsymmetricKey{
						KeyId:     resp.GetRotatedResources().GetRotatedOutKey().GetKey().GetKeyId(),
						KeyStatus: resp.GetRotatedResources().GetRotatedOutKey().GetKey().GetKeyStatus(),
					},
				},
				AttributeDefinitionMappings: resp.GetRotatedResources().GetAttributeDefinitionMappings(),
				NamespaceMappings:           resp.GetRotatedResources().GetNamespaceMappings(),
				AttributeValueMappings:      resp.GetRotatedResources().GetAttributeValueMappings(),
			},
			KasKey: &policy.KasKey{
				KasId: resp.GetKasKey().GetKasId(),
				Key: &policy.AsymmetricKey{
					KeyId:     resp.GetKasKey().GetKey().GetKeyId(),
					KeyStatus: resp.GetKasKey().GetKey().GetKeyStatus(),
				},
			},
		}
		s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

		return nil
	})
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextKeyRotationFailed, slog.String("active_key_id", objectID), slog.String("new_key_id", r.Msg.GetNewKey().GetKeyId()))
	}

	// Implementation for RotateKey
	return connect.NewResponse(resp), nil
}

func (s KeyAccessServerRegistry) SetBaseKey(ctx context.Context, r *connect.Request[kasr.SetBaseKeyRequest]) (*connect.Response[kasr.SetBaseKeyResponse], error) {
	resp := &kasr.SetBaseKeyResponse{}

	var objectID string
	switch i := r.Msg.GetActiveKey().(type) {
	case *kasr.SetBaseKeyRequest_Id:
		s.logger.DebugContext(ctx, "setting base key by ID", slog.String("id", i.Id))
		objectID = i.Id
	case *kasr.SetBaseKeyRequest_Key:
		s.logger.DebugContext(ctx, "setting base key by Key ID", slog.String("active_key_id", i.Key.GetKid()))
		objectID = i.Key.GetKid()
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, nil)
	}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeKasRegistryKeys,
		ObjectID:   objectID,
	}

	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		var err error
		resp, err = txClient.SetBaseKey(ctx, r.Msg)
		if err != nil {
			s.logger.ErrorContext(ctx, "failed to set default key", slog.String("error", err.Error()))
			s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return err
		}

		auditParams.Original = resp.GetPreviousBaseKey()
		auditParams.Updated = resp.GetNewBaseKey()
		s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

		return nil
	})
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("set_default_key", r.Msg.GetId()))
	}

	return connect.NewResponse(resp), nil
}

func (s KeyAccessServerRegistry) GetBaseKey(ctx context.Context, _ *connect.Request[kasr.GetBaseKeyRequest]) (*connect.Response[kasr.GetBaseKeyResponse], error) {
	s.logger.DebugContext(ctx, "getting Base Key")
	resp := &kasr.GetBaseKeyResponse{}

	key, err := s.dbClient.GetBaseKey(ctx)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed)
	}
	resp.BaseKey = key
	return connect.NewResponse(resp), nil
}

func (s KeyAccessServerRegistry) ListKeyMappings(ctx context.Context, r *connect.Request[kasr.ListKeyMappingsRequest]) (*connect.Response[kasr.ListKeyMappingsResponse], error) {
	if r.Msg.GetIdentifier() != nil {
		s.logger.DebugContext(ctx, "listing key mappings with identifier", slog.Any("identifier", r.Msg.GetIdentifier()))
	} else {
		s.logger.DebugContext(ctx, "listing key mappings without identifier")
	}

	resp, err := s.dbClient.ListKeyMappings(ctx, r.Msg)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed)
	}
	return connect.NewResponse(resp), nil
}
