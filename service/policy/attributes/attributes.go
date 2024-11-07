package attributes

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/attributes/attributesconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policydb "github.com/opentdf/platform/service/policy/db"
	"google.golang.org/protobuf/encoding/protojson"
)

type AttributesService struct { //nolint:revive // AttributesService is a valid name for this struct
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
}

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[attributesconnect.AttributesServiceHandler] {
	return &serviceregistry.Service[attributesconnect.AttributesServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[attributesconnect.AttributesServiceHandler]{
			Namespace:      ns,
			DB:             dbRegister,
			ServiceDesc:    &attributes.AttributesService_ServiceDesc,
			ConnectRPCFunc: attributesconnect.NewAttributesServiceHandler,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (attributesconnect.AttributesServiceHandler, serviceregistry.HandlerServer) {
				as := &AttributesService{dbClient: policydb.NewClient(srp.DBClient, srp.Logger), logger: srp.Logger}
				return as, func(_ context.Context, mux *http.ServeMux) error {
					mux.HandleFunc(fmt.Sprintf("%s /attributes/*/fqn", http.MethodGet), as.GetAttributeValuesByFqnsHandler)
					return nil
				}
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

	item, err := s.dbClient.CreateAttribute(ctx, req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("attribute", req.Msg.String()))
	}

	s.logger.Debug("created new attribute definition", slog.String("name", req.Msg.GetName()))

	auditParams.ObjectID = item.GetId()
	auditParams.Original = item
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.Attribute = item
	return connect.NewResponse(rsp), nil
}

func (s *AttributesService) ListAttributes(ctx context.Context,
	req *connect.Request[attributes.ListAttributesRequest],
) (*connect.Response[attributes.ListAttributesResponse], error) {
	state := policydb.GetDBStateTypeTransformedEnum(req.Msg.GetState())
	namespace := req.Msg.GetNamespace()
	s.logger.Debug("listing attribute definitions", slog.String("state", state))
	rsp := &attributes.ListAttributesResponse{}

	list, err := s.dbClient.ListAttributes(ctx, state, namespace)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}
	rsp.Attributes = list

	return connect.NewResponse(rsp), nil
}

func (s *AttributesService) GetAttribute(ctx context.Context,
	req *connect.Request[attributes.GetAttributeRequest],
) (*connect.Response[attributes.GetAttributeResponse], error) {
	rsp := &attributes.GetAttributeResponse{}

	item, err := s.dbClient.GetAttribute(ctx, req.Msg.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.Msg.GetId()))
	}
	rsp.Attribute = item

	return connect.NewResponse(rsp), err
}

func (s *AttributesService) GetAttributeValuesByFqns(ctx context.Context,
	req *connect.Request[attributes.GetAttributeValuesByFqnsRequest],
) (*connect.Response[attributes.GetAttributeValuesByFqnsResponse], error) {
	rsp := &attributes.GetAttributeValuesByFqnsResponse{}

	fqnsToAttributes, err := s.dbClient.GetAttributesByValueFqns(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("fqns", fmt.Sprintf("%v", req.Msg.GetFqns())))
	}
	rsp.FqnAttributeValues = fqnsToAttributes

	return connect.NewResponse(rsp), nil
}

func (s *AttributesService) GetAttributeValuesByFqnsHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	fqns := q["fqns"]
	withAttrGrants, err := strconv.ParseBool(q.Get("withValue.withAttribute.withKeyAccessGrants"))
	if err != nil {
		s.logger.Error("failed to parse withValue.withAttribute.withKeyAccessGrants", slog.String("error", err.Error()))
		withAttrGrants = false
	}

	withGrants, err := strconv.ParseBool(q.Get("withValue.withKeyAccessGrants"))
	if err != nil {
		s.logger.Error("failed to parse withValue.withKeyAccessGrants", slog.String("error", err.Error()))
		withGrants = false
	}

	fqnsToAttributes, err := s.dbClient.GetAttributesByValueFqns(r.Context(), &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: fqns,
		WithValue: &policy.AttributeValueSelector{
			WithKeyAccessGrants: withGrants,
			WithAttribute: &policy.AttributeValueSelector_AttributeSelector{
				WithKeyAccessGrants: withAttrGrants,
			},
		},
	})
	if err != nil {
		s.logger.Error("failed to get attribute values by fqns", slog.String("error", err.Error()))
		http.Error(w, "failed to get attribute values by fqns", http.StatusInternalServerError)
		return
	}
	fqnsToAttributesBytes, err := protojson.Marshal(&attributes.GetAttributeValuesByFqnsResponse{FqnAttributeValues: fqnsToAttributes})
	if err != nil {
		s.logger.Error("failed to marshal attribute values by fqns", slog.String("error", err.Error()))
		http.Error(w, "failed to marshal attribute values by fqns", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err = w.Write(fqnsToAttributesBytes); err != nil {
		s.logger.Error("failed to write attribute values by fqns", slog.String("error", err.Error()))
	}
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

	item, err := s.dbClient.CreateAttributeValue(ctx, req.Msg.GetAttributeId(), req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("attributeId", req.Msg.GetAttributeId()), slog.String("value", req.Msg.String()))
	}

	auditParams.ObjectID = item.GetId()
	auditParams.Original = item
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.Value = item
	return connect.NewResponse(rsp), nil
}

func (s *AttributesService) ListAttributeValues(ctx context.Context, req *connect.Request[attributes.ListAttributeValuesRequest]) (*connect.Response[attributes.ListAttributeValuesResponse], error) {
	rsp := &attributes.ListAttributeValuesResponse{}

	state := policydb.GetDBStateTypeTransformedEnum(req.Msg.GetState())
	s.logger.Debug("listing attribute values", slog.String("attributeId", req.Msg.GetAttributeId()), slog.String("state", state))
	list, err := s.dbClient.ListAttributeValues(ctx, req.Msg.GetAttributeId(), state)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed, slog.String("attributeId", req.Msg.GetAttributeId()))
	}

	rsp.Values = list

	return connect.NewResponse(rsp), nil
}

func (s *AttributesService) GetAttributeValue(ctx context.Context, req *connect.Request[attributes.GetAttributeValueRequest]) (*connect.Response[attributes.GetAttributeValueResponse], error) {
	rsp := &attributes.GetAttributeValueResponse{}

	item, err := s.dbClient.GetAttributeValue(ctx, req.Msg.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.Msg.GetId()))
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
