package attributes

import (
	"context"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/attributes/attributesconnect"
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
				return as, nil
			},
		},
	}
}

func (s AttributesService) CreateAttribute(ctx context.Context,
	req *connect.Request[attributes.CreateAttributeRequest],
) (*connect.Response[attributes.CreateAttributeResponse], error) {
	s.logger.Debug("creating new attribute definition", slog.String("name", req.Msg.GetName()))
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

		s.logger.Debug("created new attribute definition", slog.String("name", req.Msg.GetName()))

		auditParams.ObjectID = item.GetId()
		auditParams.Original = item
		s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

		rsp.Attribute = item
		return nil
	})
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("attribute", req.Msg.String()))
	}

	return connect.NewResponse(rsp), nil
}

func (s *AttributesService) ListAttributes(ctx context.Context,
	req *connect.Request[attributes.ListAttributesRequest],
) (*connect.Response[attributes.ListAttributesResponse], error) {
	ctx, span := s.Tracer.Start(ctx, "ListAttributes")
	defer span.End()

	state := req.Msg.GetState().String()
	s.logger.Debug("listing attribute definitions", slog.String("state", state))

	rsp, err := s.dbClient.ListAttributes(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	return connect.NewResponse(rsp), nil
}

func (s *AttributesService) GetAttribute(ctx context.Context,
	req *connect.Request[attributes.GetAttributeRequest],
) (*connect.Response[attributes.GetAttributeResponse], error) {
	ctx, span := s.Tracer.Start(ctx, "GetAttribute")
	defer span.End()

	rsp := &attributes.GetAttributeResponse{}

	var identifier any

	if req.Msg.GetId() != "" { //nolint:staticcheck // Id can still be used until removed
		identifier = req.Msg.GetId() //nolint:staticcheck // Id can still be used until removed
	} else {
		identifier = req.Msg.GetIdentifier()
	}

	item, err := s.dbClient.GetAttribute(ctx, identifier)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.Any("id", identifier))
	}
	rsp.Attribute = item

	return connect.NewResponse(rsp), err
}

func (s *AttributesService) GetAttributeValuesByFqns(ctx context.Context,
	req *connect.Request[attributes.GetAttributeValuesByFqnsRequest],
) (*connect.Response[attributes.GetAttributeValuesByFqnsResponse], error) {
	ctx, span := s.Tracer.Start(ctx, "GetAttributeValuesByFqns")
	defer span.End()

	rsp := &attributes.GetAttributeValuesByFqnsResponse{}

	fqnsToAttributes, err := s.dbClient.GetAttributesByValueFqns(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("fqns", fmt.Sprintf("%v", req.Msg.GetFqns())))
	}
	rsp.FqnAttributeValues = fqnsToAttributes

	return connect.NewResponse(rsp), nil
}

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

	original, err := s.dbClient.GetAttribute(ctx, attributeID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", attributeID))
	}

	updated, err := s.dbClient.UpdateAttribute(ctx, attributeID, req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.Msg.GetId()), slog.String("attribute", req.Msg.String()))
	}

	auditParams.Original = original
	auditParams.Updated = updated
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.Attribute = &policy.Attribute{
		Id: attributeID,
	}

	return connect.NewResponse(rsp), nil
}

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

	original, err := s.dbClient.GetAttribute(ctx, attributeID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", attributeID))
	}

	updated, err := s.dbClient.DeactivateAttribute(ctx, attributeID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeactivationFailed, slog.String("id", attributeID))
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
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("value", req.Msg.String()))
	}

	return connect.NewResponse(rsp), nil
}

func (s *AttributesService) ListAttributeValues(ctx context.Context, req *connect.Request[attributes.ListAttributeValuesRequest]) (*connect.Response[attributes.ListAttributeValuesResponse], error) {
	state := req.Msg.GetState().String()
	s.logger.Debug("listing attribute values", slog.String("attributeId", req.Msg.GetAttributeId()), slog.String("state", state))
	rsp, err := s.dbClient.ListAttributeValues(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed, slog.String("attributeId", req.Msg.GetAttributeId()))
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
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.Any("id", identifier))
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
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", attributeID))
	}

	updated, err := s.dbClient.UpdateAttributeValue(ctx, req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.Msg.GetId()), slog.String("value", req.Msg.String()))
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
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", attributeID))
	}

	updated, err := s.dbClient.DeactivateAttributeValue(ctx, attributeID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeactivationFailed, slog.String("id", attributeID))
	}

	auditParams.Original = original
	auditParams.Updated = updated
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.Value = updated

	return connect.NewResponse(rsp), nil
}

func (s *AttributesService) AssignKeyAccessServerToAttribute(ctx context.Context, req *connect.Request[attributes.AssignKeyAccessServerToAttributeRequest]) (*connect.Response[attributes.AssignKeyAccessServerToAttributeResponse], error) {
	rsp := &attributes.AssignKeyAccessServerToAttributeResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeKasAttributeDefinitionAssignment,
		ObjectID:   fmt.Sprintf("%s-%s", req.Msg.GetAttributeKeyAccessServer().GetAttributeId(), req.Msg.GetAttributeKeyAccessServer().GetKeyAccessServerId()),
	}

	attributeKas, err := s.dbClient.AssignKeyAccessServerToAttribute(ctx, req.Msg.GetAttributeKeyAccessServer())
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("attributeKas", req.Msg.GetAttributeKeyAccessServer().String()))
	}
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.AttributeKeyAccessServer = attributeKas

	return connect.NewResponse(rsp), nil
}

func (s *AttributesService) RemoveKeyAccessServerFromAttribute(ctx context.Context, req *connect.Request[attributes.RemoveKeyAccessServerFromAttributeRequest]) (*connect.Response[attributes.RemoveKeyAccessServerFromAttributeResponse], error) {
	rsp := &attributes.RemoveKeyAccessServerFromAttributeResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeKasAttributeDefinitionAssignment,
		ObjectID:   fmt.Sprintf("%s-%s", req.Msg.GetAttributeKeyAccessServer().GetAttributeId(), req.Msg.GetAttributeKeyAccessServer().GetKeyAccessServerId()),
	}

	attributeKas, err := s.dbClient.RemoveKeyAccessServerFromAttribute(ctx, req.Msg.GetAttributeKeyAccessServer())
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("attributeKas", req.Msg.GetAttributeKeyAccessServer().String()))
	}
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.AttributeKeyAccessServer = attributeKas

	return connect.NewResponse(rsp), nil
}

func (s *AttributesService) AssignKeyAccessServerToValue(ctx context.Context, req *connect.Request[attributes.AssignKeyAccessServerToValueRequest]) (*connect.Response[attributes.AssignKeyAccessServerToValueResponse], error) {
	rsp := &attributes.AssignKeyAccessServerToValueResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeKasAttributeValueAssignment,
		ObjectID:   fmt.Sprintf("%s-%s", req.Msg.GetValueKeyAccessServer().GetValueId(), req.Msg.GetValueKeyAccessServer().GetKeyAccessServerId()),
	}

	valueKas, err := s.dbClient.AssignKeyAccessServerToValue(ctx, req.Msg.GetValueKeyAccessServer())
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("attributeValueKas", req.Msg.GetValueKeyAccessServer().String()))
	}
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.ValueKeyAccessServer = valueKas

	return connect.NewResponse(rsp), nil
}

func (s *AttributesService) RemoveKeyAccessServerFromValue(ctx context.Context, req *connect.Request[attributes.RemoveKeyAccessServerFromValueRequest]) (*connect.Response[attributes.RemoveKeyAccessServerFromValueResponse], error) {
	rsp := &attributes.RemoveKeyAccessServerFromValueResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeKasAttributeValueAssignment,
		ObjectID:   fmt.Sprintf("%s-%s", req.Msg.GetValueKeyAccessServer().GetValueId(), req.Msg.GetValueKeyAccessServer().GetKeyAccessServerId()),
	}

	valueKas, err := s.dbClient.RemoveKeyAccessServerFromValue(ctx, req.Msg.GetValueKeyAccessServer())
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("attributeValueKas", req.Msg.GetValueKeyAccessServer().String()))
	}
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.ValueKeyAccessServer = valueKas

	return connect.NewResponse(rsp), nil
}

func (s *AttributesService) AssignKeyToAttribute(context.Context, *connect.Request[attributes.AssignKeyToAttributeRequest]) (*connect.Response[attributes.AssignKeyToAttributeResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}

func (s *AttributesService) RemoveKeyFromAttribute(context.Context, *connect.Request[attributes.RemoveKeyFromAttributeRequest]) (*connect.Response[attributes.RemoveKeyFromAttributeResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}

func (s *AttributesService) AssignKeyToValue(context.Context, *connect.Request[attributes.AssignKeyToValueRequest]) (*connect.Response[attributes.AssignKeyToValueResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}

func (s *AttributesService) RemoveKeyFromValue(context.Context, *connect.Request[attributes.RemoveKeyFromValueRequest]) (*connect.Response[attributes.RemoveKeyFromValueResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}

func (s *AttributesService) AssignPublicKeyToAttribute(context.Context, *connect.Request[attributes.AssignPublicKeyToAttributeRequest]) (*connect.Response[attributes.AssignPublicKeyToAttributeResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}

func (s *AttributesService) RemovePublicKeyFromAttribute(context.Context, *connect.Request[attributes.RemovePublicKeyFromAttributeRequest]) (*connect.Response[attributes.RemovePublicKeyFromAttributeResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}

func (s *AttributesService) AssignPublicKeyToValue(context.Context, *connect.Request[attributes.AssignPublicKeyToValueRequest]) (*connect.Response[attributes.AssignPublicKeyToValueResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}

func (s *AttributesService) RemovePublicKeyFromValue(context.Context, *connect.Request[attributes.RemovePublicKeyFromValueRequest]) (*connect.Response[attributes.RemovePublicKeyFromValueResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}
