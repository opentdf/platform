package attributes

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/attributes/attributesconnect"
	"github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
	"go.opentelemetry.io/otel/trace"
)

type AttributesService struct { //nolint:revive // AttributesService is a valid name for this struct
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
	config   *policyconfig.Config
	trace.Tracer
}

func OnConfigUpdate(as *AttributesService) serviceregistry.OnConfigUpdateHook {
	return func(_ context.Context, cfg config.ServiceConfig) error {
		sharedCfg, err := policyconfig.GetSharedPolicyConfig(cfg)
		if err != nil {
			return fmt.Errorf("failed to get shared policy config: %w", err)
		}
		as.config = sharedCfg
		as.dbClient = policydb.NewClient(as.dbClient.Client, as.logger, int32(sharedCfg.ListRequestLimitMax), int32(sharedCfg.ListRequestLimitDefault))

		as.logger.Info("attributes service config reloaded")

		return nil
	}
}

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[attributesconnect.AttributesServiceHandler] {
	as := new(AttributesService)
	onUpdateConfigHook := OnConfigUpdate(as)

	return &serviceregistry.Service[attributesconnect.AttributesServiceHandler]{
		Close: as.Close,
		ServiceOptions: serviceregistry.ServiceOptions[attributesconnect.AttributesServiceHandler]{
			Namespace:       ns,
			DB:              dbRegister,
			ServiceDesc:     &attributes.AttributesService_ServiceDesc,
			ConnectRPCFunc:  attributesconnect.NewAttributesServiceHandler,
			GRPCGatewayFunc: attributes.RegisterAttributesServiceHandler,
			OnConfigUpdate:  onUpdateConfigHook,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (attributesconnect.AttributesServiceHandler, serviceregistry.HandlerServer) {
				logger := srp.Logger
				cfg, err := policyconfig.GetSharedPolicyConfig(srp.Config)
				if err != nil {
					logger.Error("error getting attributes service policy config", slog.String("error", err.Error()))
					panic(err)
				}
				as.Tracer = srp.Tracer
				as.logger = logger
				as.dbClient = policydb.NewClient(srp.DBClient, logger, int32(cfg.ListRequestLimitMax), int32(cfg.ListRequestLimitDefault))
				as.config = cfg

				// Register authz resolvers per-method
				// Each resolver extracts authorization dimensions from the request, performing DB lookups as needed.
				// The resolver is called by the auth interceptor before the handler.
				if srp.AuthzResolverRegistry != nil {
					srp.AuthzResolverRegistry.MustRegister("CreateAttribute", as.createAttributeAuthzResolver)
					srp.AuthzResolverRegistry.MustRegister("GetAttribute", as.getAttributeAuthzResolver)
					srp.AuthzResolverRegistry.MustRegister("GetAttributeValuesByFqns", as.getAttributeValuesByFqnsAuthzResolver)
					srp.AuthzResolverRegistry.MustRegister("ListAttributes", as.listAttributesAuthzResolver)
					srp.AuthzResolverRegistry.MustRegister("UpdateAttribute", as.updateAttributeAuthzResolver)
					srp.AuthzResolverRegistry.MustRegister("DeactivateAttribute", as.deactivateAttributeAuthzResolver)
				}

				return as, nil
			},
		},
	}
}

// Close gracefully shuts down the service, closing the database client.
func (s *AttributesService) Close() {
	s.logger.Info("gracefully shutting down attributes service")
	s.dbClient.Close()
}

///
/// Attribute Definitions
///

// --- CreateAttribute ---

func (s *AttributesService) CreateAttribute(ctx context.Context,
	req *connect.Request[attributes.CreateAttributeRequest],
) (*connect.Response[attributes.CreateAttributeResponse], error) {
	s.logger.DebugContext(ctx, "creating new attribute definition", slog.String("name", req.Msg.GetName()))
	rsp := &attributes.CreateAttributeResponse{}

	auditParams := audit.PolicyEventParams{
		ObjectType: audit.ObjectTypeAttributeDefinition,
		ActionType: audit.ActionTypeCreate,
	}

	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		item, err := txClient.CreateAttribute(ctx, req.Msg)
		if err != nil {
			s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return err
		}

		s.logger.DebugContext(ctx, "created new attribute definition", slog.String("name", req.Msg.GetName()))

		auditParams.ObjectID = item.GetId()
		auditParams.Original = item
		s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

		rsp.Attribute = item
		return nil
	})
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextCreationFailed, slog.String("attribute", req.Msg.String()))
	}

	return connect.NewResponse(rsp), nil
}

// --- ListAttributes ---

func (s *AttributesService) ListAttributes(ctx context.Context,
	req *connect.Request[attributes.ListAttributesRequest],
) (*connect.Response[attributes.ListAttributesResponse], error) {
	ctx, span := s.Start(ctx, "ListAttributes")
	defer span.End()

	state := req.Msg.GetState().String()
	s.logger.DebugContext(ctx, "listing attribute definitions", slog.String("state", state))

	rsp, err := s.dbClient.ListAttributes(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextListRetrievalFailed)
	}

	return connect.NewResponse(rsp), nil
}

// --- GetAttribute ---

func (s *AttributesService) GetAttribute(ctx context.Context,
	req *connect.Request[attributes.GetAttributeRequest],
) (*connect.Response[attributes.GetAttributeResponse], error) {
	ctx, span := s.Start(ctx, "GetAttribute")
	defer span.End()

	rsp := &attributes.GetAttributeResponse{}

	// Check if attribute was already fetched by authz resolver (avoid duplicate DB query)
	if cached := authz.GetResolvedDataFromContext(ctx, ResolverCacheKeyAttribute); cached != nil {
		if attr, ok := cached.(*policy.Attribute); ok {
			rsp.Attribute = attr
			return connect.NewResponse(rsp), nil
		}
	}

	// Fallback to DB query if not cached (e.g., v1 authz mode or no resolver)
	var identifier any
	if req.Msg.GetId() != "" { //nolint:staticcheck // Id can still be used until removed
		identifier = req.Msg.GetId() //nolint:staticcheck // Id can still be used until removed
	} else {
		identifier = req.Msg.GetIdentifier()
	}

	item, err := s.dbClient.GetAttribute(ctx, identifier)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.Any("id", identifier))
	}
	rsp.Attribute = item

	return connect.NewResponse(rsp), nil
}

// --- GetAttributeValuesByFqns ---

func (s *AttributesService) GetAttributeValuesByFqns(ctx context.Context,
	req *connect.Request[attributes.GetAttributeValuesByFqnsRequest],
) (*connect.Response[attributes.GetAttributeValuesByFqnsResponse], error) {
	ctx, span := s.Start(ctx, "GetAttributeValuesByFqns")
	defer span.End()

	rsp := &attributes.GetAttributeValuesByFqnsResponse{}

	fqnsToAttributes, err := s.dbClient.GetAttributesByValueFqns(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("fqns", fmt.Sprintf("%v", req.Msg.GetFqns())))
	}
	rsp.FqnAttributeValues = fqnsToAttributes

	return connect.NewResponse(rsp), nil
}

// --- UpdateAttribute ---

func (s *AttributesService) UpdateAttribute(ctx context.Context,
	req *connect.Request[attributes.UpdateAttributeRequest],
) (*connect.Response[attributes.UpdateAttributeResponse], error) {
	rsp := &attributes.UpdateAttributeResponse{}

	attributeID := req.Msg.GetId()
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeAttributeDefinition,
		ObjectID:   attributeID,
	}

	// Check if attribute was already fetched by authz resolver (avoid duplicate DB query)
	var original *policy.Attribute
	if cached := authz.GetResolvedDataFromContext(ctx, ResolverCacheKeyAttribute); cached != nil {
		original, _ = cached.(*policy.Attribute)
	}

	// Fallback to DB query if not cached (e.g., v1 authz mode or no resolver)
	if original == nil {
		var err error
		original, err = s.dbClient.GetAttribute(ctx, attributeID)
		if err != nil {
			s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", attributeID))
		}
	}

	updated, err := s.dbClient.UpdateAttribute(ctx, attributeID, req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("id", req.Msg.GetId()), slog.String("attribute", req.Msg.String()))
	}

	auditParams.Original = original
	auditParams.Updated = updated
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.Attribute = &policy.Attribute{
		Id: attributeID,
	}

	return connect.NewResponse(rsp), nil
}

// --- DeactivateAttribute ---

func (s *AttributesService) DeactivateAttribute(ctx context.Context,
	req *connect.Request[attributes.DeactivateAttributeRequest],
) (*connect.Response[attributes.DeactivateAttributeResponse], error) {
	rsp := &attributes.DeactivateAttributeResponse{}

	attributeID := req.Msg.GetId()
	auditParams := audit.PolicyEventParams{
		ObjectType: audit.ObjectTypeAttributeDefinition,
		ActionType: audit.ActionTypeUpdate,
		ObjectID:   attributeID,
	}

	// Check if attribute was already fetched by authz resolver (avoid duplicate DB query)
	var original *policy.Attribute
	if cached := authz.GetResolvedDataFromContext(ctx, ResolverCacheKeyAttribute); cached != nil {
		original, _ = cached.(*policy.Attribute)
	}

	// Fallback to DB query if not cached (e.g., v1 authz mode or no resolver)
	if original == nil {
		var err error
		original, err = s.dbClient.GetAttribute(ctx, attributeID)
		if err != nil {
			s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", attributeID))
		}
	}

	updated, err := s.dbClient.DeactivateAttribute(ctx, attributeID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeactivationFailed, slog.String("id", attributeID))
	}

	auditParams.Original = original
	auditParams.Updated = updated
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.Attribute = &policy.Attribute{
		Id: attributeID,
	}
	return connect.NewResponse(rsp), nil
}

///
/// Attribute Values
///

func (s *AttributesService) CreateAttributeValue(ctx context.Context, req *connect.Request[attributes.CreateAttributeValueRequest]) (*connect.Response[attributes.CreateAttributeValueResponse], error) {
	rsp := &attributes.CreateAttributeValueResponse{}

	auditParams := audit.PolicyEventParams{
		ObjectType: audit.ObjectTypeAttributeValue,
		ActionType: audit.ActionTypeCreate,
	}

	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		item, err := txClient.CreateAttributeValue(ctx, req.Msg.GetAttributeId(), req.Msg)
		if err != nil {
			s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return err
		}

		auditParams.ObjectID = item.GetId()
		auditParams.Original = item
		s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

		rsp.Value = item

		return nil
	})
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextCreationFailed, slog.String("value", req.Msg.String()))
	}

	return connect.NewResponse(rsp), nil
}

func (s *AttributesService) ListAttributeValues(ctx context.Context, req *connect.Request[attributes.ListAttributeValuesRequest]) (*connect.Response[attributes.ListAttributeValuesResponse], error) {
	state := req.Msg.GetState().String()
	s.logger.DebugContext(ctx,
		"listing attribute values",
		slog.String("attribute_id", req.Msg.GetAttributeId()),
		slog.String("state", state),
	)
	rsp, err := s.dbClient.ListAttributeValues(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextListRetrievalFailed, slog.String("attributeId", req.Msg.GetAttributeId()))
	}

	return connect.NewResponse(rsp), nil
}

func (s *AttributesService) GetAttributeValue(ctx context.Context, req *connect.Request[attributes.GetAttributeValueRequest]) (*connect.Response[attributes.GetAttributeValueResponse], error) {
	rsp := &attributes.GetAttributeValueResponse{}

	var identifier any

	if req.Msg.GetId() != "" { //nolint:staticcheck // Id can still be used until removed
		identifier = req.Msg.GetId() //nolint:staticcheck // Id can still be used until removed
	} else {
		identifier = req.Msg.GetIdentifier()
	}

	item, err := s.dbClient.GetAttributeValue(ctx, identifier)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.Any("id", identifier))
	}

	rsp.Value = item

	return connect.NewResponse(rsp), nil
}

func (s *AttributesService) UpdateAttributeValue(ctx context.Context, req *connect.Request[attributes.UpdateAttributeValueRequest]) (*connect.Response[attributes.UpdateAttributeValueResponse], error) {
	rsp := &attributes.UpdateAttributeValueResponse{}

	attributeID := req.Msg.GetId()
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeAttributeValue,
		ObjectID:   attributeID,
	}

	original, err := s.dbClient.GetAttributeValue(ctx, attributeID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", attributeID))
	}

	updated, err := s.dbClient.UpdateAttributeValue(ctx, req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("id", req.Msg.GetId()), slog.String("value", req.Msg.String()))
	}

	auditParams.Original = original
	auditParams.Updated = updated
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.Value = &policy.Value{
		Id: attributeID,
	}

	return connect.NewResponse(rsp), nil
}

func (s *AttributesService) DeactivateAttributeValue(ctx context.Context, req *connect.Request[attributes.DeactivateAttributeValueRequest]) (*connect.Response[attributes.DeactivateAttributeValueResponse], error) {
	rsp := &attributes.DeactivateAttributeValueResponse{}

	attributeID := req.Msg.GetId()
	auditParams := audit.PolicyEventParams{
		ObjectType: audit.ObjectTypeAttributeValue,
		ActionType: audit.ActionTypeDelete,
		ObjectID:   attributeID,
	}

	original, err := s.dbClient.GetAttributeValue(ctx, attributeID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", attributeID))
	}

	updated, err := s.dbClient.DeactivateAttributeValue(ctx, attributeID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeactivationFailed, slog.String("id", attributeID))
	}

	auditParams.Original = original
	auditParams.Updated = updated
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.Value = updated

	return connect.NewResponse(rsp), nil
}

func (s *AttributesService) AssignKeyAccessServerToAttribute(_ context.Context, _ *connect.Request[attributes.AssignKeyAccessServerToAttributeRequest]) (*connect.Response[attributes.AssignKeyAccessServerToAttributeResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("this compatibility stub will be removed entirely in the following release"))
}

func (s *AttributesService) RemoveKeyAccessServerFromAttribute(ctx context.Context, req *connect.Request[attributes.RemoveKeyAccessServerFromAttributeRequest]) (*connect.Response[attributes.RemoveKeyAccessServerFromAttributeResponse], error) {
	rsp := &attributes.RemoveKeyAccessServerFromAttributeResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeKasAttributeDefinitionAssignment,
	}

	attributeKas, err := s.dbClient.RemoveKeyAccessServerFromAttribute(ctx, req.Msg.GetAttributeKeyAccessServer())
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("attributeKas", req.Msg.GetAttributeKeyAccessServer().String()))
	}

	auditParams.ObjectID = attributeKas.GetAttributeId()
	auditParams.Original = req.Msg.GetAttributeKeyAccessServer()
	auditParams.Updated = attributeKas
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.AttributeKeyAccessServer = attributeKas

	return connect.NewResponse(rsp), nil
}

func (s *AttributesService) AssignKeyAccessServerToValue(_ context.Context, _ *connect.Request[attributes.AssignKeyAccessServerToValueRequest]) (*connect.Response[attributes.AssignKeyAccessServerToValueResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("this compatibility stub will be removed entirely in the following release"))
}

func (s *AttributesService) RemoveKeyAccessServerFromValue(ctx context.Context, req *connect.Request[attributes.RemoveKeyAccessServerFromValueRequest]) (*connect.Response[attributes.RemoveKeyAccessServerFromValueResponse], error) {
	rsp := &attributes.RemoveKeyAccessServerFromValueResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeKasAttributeValueAssignment,
	}

	valueKas, err := s.dbClient.RemoveKeyAccessServerFromValue(ctx, req.Msg.GetValueKeyAccessServer())
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("attributeValueKas", req.Msg.GetValueKeyAccessServer().String()))
	}

	auditParams.ObjectID = valueKas.GetValueId()
	auditParams.Original = req.Msg.GetValueKeyAccessServer()
	auditParams.Updated = valueKas
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.ValueKeyAccessServer = valueKas

	return connect.NewResponse(rsp), nil
}

func (s *AttributesService) AssignPublicKeyToAttribute(ctx context.Context, r *connect.Request[attributes.AssignPublicKeyToAttributeRequest]) (*connect.Response[attributes.AssignPublicKeyToAttributeResponse], error) {
	rsp := &attributes.AssignPublicKeyToAttributeResponse{}
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeKasAttributeDefinitionKeyAssignment,
	}

	ak, err := s.dbClient.AssignPublicKeyToAttribute(ctx, r.Msg.GetAttributeKey())
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextCreationFailed, slog.String("attributeKey", r.Msg.GetAttributeKey().String()))
	}

	auditParams.ObjectID = ak.GetAttributeId()
	auditParams.Original = ak
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.AttributeKey = ak

	return connect.NewResponse(rsp), nil
}

func (s *AttributesService) RemovePublicKeyFromAttribute(ctx context.Context, r *connect.Request[attributes.RemovePublicKeyFromAttributeRequest]) (*connect.Response[attributes.RemovePublicKeyFromAttributeResponse], error) {
	rsp := &attributes.RemovePublicKeyFromAttributeResponse{}
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeKasAttributeDefinitionKeyAssignment,
	}

	ak, err := s.dbClient.RemovePublicKeyFromAttribute(ctx, r.Msg.GetAttributeKey())
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeletionFailed, slog.String("attributeKey", r.Msg.GetAttributeKey().String()))
	}

	auditParams.ObjectID = ak.GetAttributeId()
	auditParams.Original = r.Msg.GetAttributeKey()
	auditParams.Updated = ak
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	return connect.NewResponse(rsp), nil
}

func (s *AttributesService) AssignPublicKeyToValue(ctx context.Context, r *connect.Request[attributes.AssignPublicKeyToValueRequest]) (*connect.Response[attributes.AssignPublicKeyToValueResponse], error) {
	rsp := &attributes.AssignPublicKeyToValueResponse{}
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeKasAttributeValueKeyAssignment,
	}

	vk, err := s.dbClient.AssignPublicKeyToValue(ctx, r.Msg.GetValueKey())
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextCreationFailed, slog.String("attributeKey", r.Msg.GetValueKey().String()))
	}

	auditParams.ObjectID = vk.GetValueId()
	auditParams.Original = vk
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.ValueKey = vk

	return connect.NewResponse(rsp), nil
}

func (s *AttributesService) RemovePublicKeyFromValue(ctx context.Context, r *connect.Request[attributes.RemovePublicKeyFromValueRequest]) (*connect.Response[attributes.RemovePublicKeyFromValueResponse], error) {
	rsp := &attributes.RemovePublicKeyFromValueResponse{}
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeKasAttributeValueKeyAssignment,
	}

	vk, err := s.dbClient.RemovePublicKeyFromValue(ctx, r.Msg.GetValueKey())
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeletionFailed, slog.String("attributeKey", r.Msg.GetValueKey().String()))
	}

	auditParams.ObjectID = vk.GetValueId()
	auditParams.Original = r.Msg.GetValueKey()
	auditParams.Updated = vk
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	return connect.NewResponse(rsp), nil
}

///
/// Authz Resolvers
///
/// These methods resolve authorization dimensions from requests.
/// They are placed at the end of the file per linting rules (unexported methods after exported).

// ResolverCacheKeyAttribute is the key used to cache fetched attributes in the ResolverContext.
// Handlers can retrieve the cached attribute via authz.GetResolvedDataFromContext(ctx, ResolverCacheKeyAttribute).
const ResolverCacheKeyAttribute = "attribute"

// createAttributeAuthzResolver resolves namespace from the request's namespace_id.
func (s *AttributesService) createAttributeAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	resolverCtx := authz.NewResolverContext()
	msg, ok := req.Any().(*attributes.CreateAttributeRequest)
	if !ok {
		return resolverCtx, fmt.Errorf("unexpected request type: %T", req.Any())
	}

	ns, err := s.dbClient.GetNamespace(ctx, msg.GetNamespaceId())
	if err != nil {
		return resolverCtx, fmt.Errorf("failed to resolve namespace for authz: %w", err)
	}

	res := resolverCtx.NewResource()
	res.AddDimension("namespace", ns.GetName())

	return resolverCtx, nil
}

// listAttributesAuthzResolver resolves optional namespace filter.
func (s *AttributesService) listAttributesAuthzResolver(_ context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	resolverCtx := authz.NewResolverContext()
	msg, ok := req.Any().(*attributes.ListAttributesRequest)
	if !ok {
		return resolverCtx, fmt.Errorf("unexpected request type: %T", req.Any())
	}

	res := resolverCtx.NewResource()
	// Namespace filter is optional - empty means "all accessible namespaces"
	if ns := msg.GetNamespace(); ns != "" {
		res.AddDimension("namespace", ns)
	}

	return resolverCtx, nil
}

// getAttributeAuthzResolver resolves namespace from attribute lookup.
func (s *AttributesService) getAttributeAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	resolverCtx := authz.NewResolverContext()
	msg, ok := req.Any().(*attributes.GetAttributeRequest)
	if !ok {
		return resolverCtx, fmt.Errorf("unexpected request type: %T", req.Any())
	}

	var identifier any
	if msg.GetId() != "" { //nolint:staticcheck // Id can still be used until removed
		identifier = msg.GetId() //nolint:staticcheck // Id can still be used until removed
	} else {
		identifier = msg.GetIdentifier()
	}

	attr, err := s.dbClient.GetAttribute(ctx, identifier)
	if err != nil {
		return resolverCtx, fmt.Errorf("failed to resolve attribute for authz: %w", err)
	}

	res := resolverCtx.NewResource()
	res.AddDimension("namespace", attr.GetNamespace().GetName())
	res.AddDimension("attribute", attr.GetName())

	// Cache the fetched attribute for handler reuse (avoids duplicate DB query)
	resolverCtx.SetResolvedData(ResolverCacheKeyAttribute, attr)

	return resolverCtx, nil
}

// updateAttributeAuthzResolver resolves namespace from attribute lookup.
func (s *AttributesService) updateAttributeAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	resolverCtx := authz.NewResolverContext()
	msg, ok := req.Any().(*attributes.UpdateAttributeRequest)
	if !ok {
		return resolverCtx, fmt.Errorf("unexpected request type: %T", req.Any())
	}

	attr, err := s.dbClient.GetAttribute(ctx, msg.GetId())
	if err != nil {
		return resolverCtx, fmt.Errorf("failed to resolve attribute for authz: %w", err)
	}

	res := resolverCtx.NewResource()
	res.AddDimension("namespace", attr.GetNamespace().GetName())
	res.AddDimension("attribute", attr.GetName())

	// Cache the fetched attribute for handler reuse (avoids duplicate DB query)
	resolverCtx.SetResolvedData(ResolverCacheKeyAttribute, attr)

	return resolverCtx, nil
}

// deactivateAttributeAuthzResolver resolves namespace from attribute lookup.
func (s *AttributesService) deactivateAttributeAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	resolverCtx := authz.NewResolverContext()
	msg, ok := req.Any().(*attributes.DeactivateAttributeRequest)
	if !ok {
		return resolverCtx, fmt.Errorf("unexpected request type: %T", req.Any())
	}

	attr, err := s.dbClient.GetAttribute(ctx, msg.GetId())
	if err != nil {
		return resolverCtx, fmt.Errorf("failed to resolve attribute for authz: %w", err)
	}

	res := resolverCtx.NewResource()
	res.AddDimension("namespace", attr.GetNamespace().GetName())
	res.AddDimension("attribute", attr.GetName())

	// Cache the fetched attribute for handler reuse (avoids duplicate DB query)
	resolverCtx.SetResolvedData(ResolverCacheKeyAttribute, attr)

	return resolverCtx, nil
}

// getAttributeValuesByFqnsAuthzResolver resolves namespaces from FQNs.
// FQN format: https://<namespace>/attr/<attribute_name>/value/<value_name>
// Since FQNs can span multiple namespaces, this creates a resource per unique namespace.
func (s *AttributesService) getAttributeValuesByFqnsAuthzResolver(_ context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	resolverCtx := authz.NewResolverContext()
	msg, ok := req.Any().(*attributes.GetAttributeValuesByFqnsRequest)
	if !ok {
		return resolverCtx, fmt.Errorf("unexpected request type: %T", req.Any())
	}

	// Extract unique namespaces from FQNs
	// FQN format: https://<namespace>/attr/<attribute_name>/value/<value_name>
	namespaces := make(map[string]struct{})
	for _, fqn := range msg.GetFqns() {
		parsed, err := url.Parse(fqn)
		if err != nil {
			continue // Skip malformed FQNs; DB will validate later
		}
		if parsed.Host != "" {
			namespaces[parsed.Host] = struct{}{}
		}
	}

	// Create a resource for each unique namespace
	for ns := range namespaces {
		res := resolverCtx.NewResource()
		res.AddDimension("namespace", ns)
	}

	return resolverCtx, nil
}
