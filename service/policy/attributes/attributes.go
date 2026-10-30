package attributes

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"connectrpc.com/connect/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/attributes/attributesconnectv2"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
	"go.opentelemetry.io/otel/trace"
)

var ErrDeprecatedListAttributeValues = errors.New("deprecated: ListAttributeValues has been removed. Use GetAttribute instead")

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

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[attributesconnectv2.AttributesServiceHandler] {
	as := new(AttributesService)
	onUpdateConfigHook := OnConfigUpdate(as)

	return &serviceregistry.Service[attributesconnectv2.AttributesServiceHandler]{
		Close: as.Close,
		ServiceOptions: serviceregistry.ServiceOptions[attributesconnectv2.AttributesServiceHandler]{
			Namespace:              ns,
			DB:                     dbRegister,
			ServiceDesc:            &attributes.AttributesService_ServiceDesc,
			ConnectRPCRegisterFunc: attributesconnectv2.RegisterAttributesServiceHandler,
			OnConfigUpdate:         onUpdateConfigHook,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (attributesconnectv2.AttributesServiceHandler, serviceregistry.HandlerServer) {
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

// Close gracefully shuts down the service, closing the database client.
func (s *AttributesService) Close() {
	s.logger.Info("gracefully shutting down attributes service")
	s.dbClient.Close()
}

func (s *AttributesService) CreateAttribute(ctx context.Context,
	req *attributes.CreateAttributeRequest,
) (*attributes.CreateAttributeResponse, error) {
	s.logger.DebugContext(ctx, "creating new attribute definition", slog.String("name", req.GetName()))
	rsp := &attributes.CreateAttributeResponse{}

	auditParams := audit.PolicyEventParams{
		ObjectType: audit.ObjectTypeAttributeDefinition,
		ActionType: audit.ActionTypeCreate,
	}

	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		item, err := txClient.CreateAttribute(ctx, req)
		if err != nil {
			return err
		}

		s.logger.DebugContext(ctx, "created new attribute definition", slog.String("name", req.GetName()))

		auditParams.ObjectID = item.GetId()
		auditParams.Original = item
		rsp.Attribute = item
		return nil
	})
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextCreationFailed, slog.String("attribute", req.String()))
	}
	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	return rsp, nil
}

func (s *AttributesService) ListAttributes(ctx context.Context,
	req *attributes.ListAttributesRequest,
) (*attributes.ListAttributesResponse, error) {
	ctx, span := s.Start(ctx, "ListAttributes")
	defer span.End()

	state := req.GetState().String()
	s.logger.DebugContext(ctx, "listing attribute definitions", slog.String("state", state))

	rsp, err := s.dbClient.ListAttributes(ctx, req)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextListRetrievalFailed)
	}

	return rsp, nil
}

func (s *AttributesService) GetAttribute(ctx context.Context,
	req *attributes.GetAttributeRequest,
) (*attributes.GetAttributeResponse, error) {
	ctx, span := s.Start(ctx, "GetAttribute")
	defer span.End()

	rsp := &attributes.GetAttributeResponse{}

	var identifier any

	if req.GetId() != "" { //nolint:staticcheck // Id can still be used until removed
		identifier = req.GetId() //nolint:staticcheck // Id can still be used until removed
	} else {
		identifier = req.GetIdentifier()
	}

	item, err := s.dbClient.GetAttribute(ctx, identifier)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.Any("id", identifier))
	}
	rsp.Attribute = item

	return rsp, err
}

func (s *AttributesService) GetAttributeValuesByFqns(ctx context.Context,
	req *attributes.GetAttributeValuesByFqnsRequest,
) (*attributes.GetAttributeValuesByFqnsResponse, error) {
	ctx, span := s.Start(ctx, "GetAttributeValuesByFqns")
	defer span.End()

	rsp := &attributes.GetAttributeValuesByFqnsResponse{}

	fqnsToAttributes, err := s.dbClient.GetAttributesByValueFqns(ctx, req)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("fqns", fmt.Sprintf("%v", req.GetFqns())))
	}
	rsp.FqnAttributeValues = fqnsToAttributes

	return rsp, nil
}

func (s *AttributesService) GetKeyMappingsByFqns(ctx context.Context,
	req *attributes.GetKeyMappingsByFqnsRequest,
) (*attributes.GetKeyMappingsByFqnsResponse, error) {
	ctx, span := s.Start(ctx, "GetKeyMappingsByFqns")
	defer span.End()

	rsp := &attributes.GetKeyMappingsByFqnsResponse{}

	mappings, err := s.dbClient.GetKeyMappingsByFqns(ctx, req)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("fqns", fmt.Sprintf("%v", req.GetFqns())))
	}
	rsp.FqnKeyMappings = mappings

	return rsp, nil
}

func (s *AttributesService) GetEntitleableAttributesByFqns(ctx context.Context,
	req *attributes.GetEntitleableAttributesByFqnsRequest,
) (*attributes.GetEntitleableAttributesByFqnsResponse, error) {
	ctx, span := s.Start(ctx, "GetEntitleableAttributesByFqns")
	defer span.End()

	rsp, err := s.dbClient.GetEntitleableAttributesByFqns(ctx, req)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("fqns", fmt.Sprintf("%v", req.GetFqns())))
	}

	return rsp, nil
}

func (s *AttributesService) UpdateAttribute(ctx context.Context,
	req *attributes.UpdateAttributeRequest,
) (*attributes.UpdateAttributeResponse, error) {
	rsp := &attributes.UpdateAttributeResponse{}

	attributeID := req.GetId()
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeAttributeDefinition,
		ObjectID:   attributeID,
	}

	original, err := s.dbClient.GetAttribute(ctx, attributeID)
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", attributeID))
	}

	updated, err := s.dbClient.UpdateAttribute(ctx, attributeID, req)
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()), slog.String("attribute", req.String()))
	}

	auditParams.Original = original
	auditParams.Updated = updated
	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	rsp.Attribute = &policy.Attribute{
		Id: attributeID,
	}

	return rsp, nil
}

func (s *AttributesService) DeactivateAttribute(ctx context.Context,
	req *attributes.DeactivateAttributeRequest,
) (*attributes.DeactivateAttributeResponse, error) {
	rsp := &attributes.DeactivateAttributeResponse{}

	attributeID := req.GetId()
	auditParams := audit.PolicyEventParams{
		ObjectType: audit.ObjectTypeAttributeDefinition,
		ActionType: audit.ActionTypeUpdate,
		ObjectID:   attributeID,
	}

	original, err := s.dbClient.GetAttribute(ctx, attributeID)
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", attributeID))
	}

	updated, err := s.dbClient.DeactivateAttribute(ctx, attributeID)
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeactivationFailed, slog.String("id", attributeID))
	}

	auditParams.Original = original
	auditParams.Updated = updated
	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	rsp.Attribute = &policy.Attribute{
		Id: attributeID,
	}
	return rsp, nil
}

///
/// Attribute Values
///

func (s *AttributesService) CreateAttributeValue(ctx context.Context, req *attributes.CreateAttributeValueRequest) (*attributes.CreateAttributeValueResponse, error) {
	rsp := &attributes.CreateAttributeValueResponse{}

	auditParams := audit.PolicyEventParams{
		ObjectType: audit.ObjectTypeAttributeValue,
		ActionType: audit.ActionTypeCreate,
	}
	subjectMappingAuditParams := audit.PolicyEventParams{
		ObjectType: audit.ObjectTypeSubjectMapping,
		ActionType: audit.ActionTypeCreate,
	}
	obligationTriggerAuditParams := audit.PolicyEventParams{
		ObjectType: audit.ObjectTypeObligationTrigger,
		ActionType: audit.ActionTypeCreate,
	}

	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		item, err := txClient.CreateAttributeValue(ctx, req.GetAttributeId(), req)
		if err != nil {
			return err
		}

		auditParams.ObjectID = item.GetId()
		auditParams.Original = item
		rsp.Value = item

		return nil
	})
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		if len(req.GetSubjectMappings()) > 0 {
			s.logger.LogPolicyCRUDFailure(ctx, subjectMappingAuditParams)
		}
		if len(req.GetObligationTriggers()) > 0 {
			s.logger.LogPolicyCRUDFailure(ctx, obligationTriggerAuditParams)
		}
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextCreationFailed, slog.String("value", req.String()))
	}
	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)
	for _, mapping := range rsp.GetValue().GetSubjectMappings() {
		subjectMappingAuditParams.ObjectID = mapping.GetId()
		subjectMappingAuditParams.Original = mapping
		s.logger.LogPolicyCRUDSuccess(ctx, subjectMappingAuditParams)
	}
	for _, obligation := range rsp.GetValue().GetObligations() {
		for _, value := range obligation.GetValues() {
			for _, trigger := range value.GetTriggers() {
				obligationTriggerAuditParams.ObjectID = trigger.GetId()
				obligationTriggerAuditParams.Original = trigger
				s.logger.LogPolicyCRUDSuccess(ctx, obligationTriggerAuditParams)
			}
		}
	}

	return rsp, nil
}

func (s *AttributesService) ListAttributeValues(_ context.Context, _ *attributes.ListAttributeValuesRequest) (*attributes.ListAttributeValuesResponse, error) {
	return nil, connect.NewError(connect.CodeUnimplemented, ErrDeprecatedListAttributeValues.Error()).WithCause(ErrDeprecatedListAttributeValues)
}

func (s *AttributesService) GetAttributeValue(ctx context.Context, req *attributes.GetAttributeValueRequest) (*attributes.GetAttributeValueResponse, error) {
	rsp := &attributes.GetAttributeValueResponse{}

	var identifier any

	if req.GetId() != "" { //nolint:staticcheck // Id can still be used until removed
		identifier = req.GetId() //nolint:staticcheck // Id can still be used until removed
	} else {
		identifier = req.GetIdentifier()
	}

	item, err := s.dbClient.GetAttributeValue(ctx, identifier)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.Any("id", identifier))
	}

	rsp.Value = item

	return rsp, nil
}

func (s *AttributesService) UpdateAttributeValue(ctx context.Context, req *attributes.UpdateAttributeValueRequest) (*attributes.UpdateAttributeValueResponse, error) {
	rsp := &attributes.UpdateAttributeValueResponse{}

	attributeID := req.GetId()
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeAttributeValue,
		ObjectID:   attributeID,
	}

	original, err := s.dbClient.GetAttributeValue(ctx, attributeID)
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", attributeID))
	}

	updated, err := s.dbClient.UpdateAttributeValue(ctx, req)
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()), slog.String("value", req.String()))
	}

	auditParams.Original = original
	auditParams.Updated = updated
	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	rsp.Value = &policy.Value{
		Id: attributeID,
	}

	return rsp, nil
}

func (s *AttributesService) DeactivateAttributeValue(ctx context.Context, req *attributes.DeactivateAttributeValueRequest) (*attributes.DeactivateAttributeValueResponse, error) {
	rsp := &attributes.DeactivateAttributeValueResponse{}

	attributeID := req.GetId()
	auditParams := audit.PolicyEventParams{
		ObjectType: audit.ObjectTypeAttributeValue,
		ActionType: audit.ActionTypeDelete,
		ObjectID:   attributeID,
	}

	original, err := s.dbClient.GetAttributeValue(ctx, attributeID)
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", attributeID))
	}

	updated, err := s.dbClient.DeactivateAttributeValue(ctx, attributeID)
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeactivationFailed, slog.String("id", attributeID))
	}

	auditParams.Original = original
	auditParams.Updated = updated
	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	rsp.Value = updated

	return rsp, nil
}

func (s *AttributesService) AssignKeyAccessServerToAttribute(_ context.Context, _ *attributes.AssignKeyAccessServerToAttributeRequest) (*attributes.AssignKeyAccessServerToAttributeResponse, error) { //nolint:staticcheck // Compatibility stub for deprecated RPC.
	return nil, connect.NewError(connect.CodeUnimplemented, "this compatibility stub will be removed entirely in the following release")
}

func (s *AttributesService) RemoveKeyAccessServerFromAttribute(ctx context.Context, req *attributes.RemoveKeyAccessServerFromAttributeRequest) (*attributes.RemoveKeyAccessServerFromAttributeResponse, error) { //nolint:staticcheck // Compatibility stub for deprecated RPC.
	rsp := &attributes.RemoveKeyAccessServerFromAttributeResponse{} //nolint:staticcheck // Deprecated response retained for compatibility endpoint.

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeKasAttributeDefinitionAssignment,
	}

	attributeKas, err := s.dbClient.RemoveKeyAccessServerFromAttribute(ctx, req.GetAttributeKeyAccessServer())
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("attribute_kas", req.GetAttributeKeyAccessServer().String()))
	}

	auditParams.ObjectID = attributeKas.GetAttributeId()
	auditParams.Original = req.GetAttributeKeyAccessServer()
	auditParams.Updated = attributeKas
	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	rsp.AttributeKeyAccessServer = attributeKas

	return rsp, nil
}

func (s *AttributesService) AssignKeyAccessServerToValue(_ context.Context, _ *attributes.AssignKeyAccessServerToValueRequest) (*attributes.AssignKeyAccessServerToValueResponse, error) { //nolint:staticcheck // Compatibility stub for deprecated RPC.
	return nil, connect.NewError(connect.CodeUnimplemented, "this compatibility stub will be removed entirely in the following release")
}

func (s *AttributesService) RemoveKeyAccessServerFromValue(ctx context.Context, req *attributes.RemoveKeyAccessServerFromValueRequest) (*attributes.RemoveKeyAccessServerFromValueResponse, error) { //nolint:staticcheck // Compatibility stub for deprecated RPC.
	rsp := &attributes.RemoveKeyAccessServerFromValueResponse{} //nolint:staticcheck // Deprecated response retained for compatibility endpoint.

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeKasAttributeValueAssignment,
	}

	valueKas, err := s.dbClient.RemoveKeyAccessServerFromValue(ctx, req.GetValueKeyAccessServer())
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("attribute_value_kas", req.GetValueKeyAccessServer().String()))
	}

	auditParams.ObjectID = valueKas.GetValueId()
	auditParams.Original = req.GetValueKeyAccessServer()
	auditParams.Updated = valueKas
	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	rsp.ValueKeyAccessServer = valueKas

	return rsp, nil
}

func (s *AttributesService) AssignPublicKeyToAttribute(ctx context.Context, r *attributes.AssignPublicKeyToAttributeRequest) (*attributes.AssignPublicKeyToAttributeResponse, error) {
	rsp := &attributes.AssignPublicKeyToAttributeResponse{}
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeKasAttributeDefinitionKeyAssignment,
	}

	ak, err := s.dbClient.AssignPublicKeyToAttribute(ctx, r.GetAttributeKey())
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextCreationFailed, slog.String("attribute_key", r.GetAttributeKey().String()))
	}

	auditParams.ObjectID = ak.GetAttributeId()
	auditParams.Original = ak
	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	rsp.AttributeKey = ak

	return rsp, nil
}

func (s *AttributesService) RemovePublicKeyFromAttribute(ctx context.Context, r *attributes.RemovePublicKeyFromAttributeRequest) (*attributes.RemovePublicKeyFromAttributeResponse, error) {
	rsp := &attributes.RemovePublicKeyFromAttributeResponse{}
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeKasAttributeDefinitionKeyAssignment,
	}

	ak, err := s.dbClient.RemovePublicKeyFromAttribute(ctx, r.GetAttributeKey())
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeletionFailed, slog.String("attribute_key", r.GetAttributeKey().String()))
	}

	auditParams.ObjectID = ak.GetAttributeId()
	auditParams.Original = r.GetAttributeKey()
	auditParams.Updated = ak
	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	return rsp, nil
}

func (s *AttributesService) AssignPublicKeyToValue(ctx context.Context, r *attributes.AssignPublicKeyToValueRequest) (*attributes.AssignPublicKeyToValueResponse, error) {
	rsp := &attributes.AssignPublicKeyToValueResponse{}
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeKasAttributeValueKeyAssignment,
	}

	vk, err := s.dbClient.AssignPublicKeyToValue(ctx, r.GetValueKey())
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextCreationFailed, slog.String("value_key", r.GetValueKey().String()))
	}

	auditParams.ObjectID = vk.GetValueId()
	auditParams.Original = vk
	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	rsp.ValueKey = vk

	return rsp, nil
}

func (s *AttributesService) RemovePublicKeyFromValue(ctx context.Context, r *attributes.RemovePublicKeyFromValueRequest) (*attributes.RemovePublicKeyFromValueResponse, error) {
	rsp := &attributes.RemovePublicKeyFromValueResponse{}
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeKasAttributeValueKeyAssignment,
	}

	vk, err := s.dbClient.RemovePublicKeyFromValue(ctx, r.GetValueKey())
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeletionFailed, slog.String("value_key", r.GetValueKey().String()))
	}

	auditParams.ObjectID = vk.GetValueId()
	auditParams.Original = r.GetValueKey()
	auditParams.Updated = vk
	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	return rsp, nil
}
