package attributes

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/internal/logger"
	"github.com/opentdf/platform/service/internal/logger/audit"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type AttributesService struct { //nolint:revive // AttributesService is a valid name for this struct
	attributes.UnimplementedAttributesServiceServer
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
}

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		ServiceDesc: &attributes.AttributesService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			return &AttributesService{dbClient: policydb.NewClient(srp.DBClient), logger: srp.Logger}, func(ctx context.Context, mux *runtime.ServeMux, server any) error {
				if srv, ok := server.(attributes.AttributesServiceServer); ok {
					return attributes.RegisterAttributesServiceHandlerServer(ctx, mux, srv)
				}
				return fmt.Errorf("failed to assert server as attributes.AttributesServiceServer")
			}
		},
	}
}

func (s AttributesService) CreateAttribute(ctx context.Context,
	req *attributes.CreateAttributeRequest,
) (*attributes.CreateAttributeResponse, error) {
	s.logger.Debug("creating new attribute definition", slog.String("name", req.GetName()))
	rsp := &attributes.CreateAttributeResponse{}

	auditParams := audit.PolicyEventParams{
		ObjectType: audit.ObjectTypeAttributeDefinition,
		ActionType: audit.ActionTypeCreate,
	}

	item, err := s.dbClient.CreateAttribute(ctx, req)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("attribute", req.String()))
	}

	s.logger.Debug("created new attribute definition", slog.String("name", req.GetName()))

	auditParams.ObjectID = item.GetId()
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	return rsp, nil
}

func (s *AttributesService) ListAttributes(ctx context.Context,
	req *attributes.ListAttributesRequest,
) (*attributes.ListAttributesResponse, error) {
	state := policydb.GetDBStateTypeTransformedEnum(req.GetState())
	namespace := req.GetNamespace()
	s.logger.Debug("listing attribute definitions", slog.String("state", state))
	rsp := &attributes.ListAttributesResponse{}

	list, err := s.dbClient.ListAllAttributes(ctx, state, namespace)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}
	rsp.Attributes = list

	return rsp, nil
}

func (s *AttributesService) GetAttribute(ctx context.Context,
	req *attributes.GetAttributeRequest,
) (*attributes.GetAttributeResponse, error) {
	rsp := &attributes.GetAttributeResponse{}

	item, err := s.dbClient.GetAttribute(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}
	rsp.Attribute = item

	return rsp, err
}

func (s *AttributesService) GetAttributeValuesByFqns(ctx context.Context,
	req *attributes.GetAttributeValuesByFqnsRequest,
) (*attributes.GetAttributeValuesByFqnsResponse, error) {
	rsp := &attributes.GetAttributeValuesByFqnsResponse{}

	fqnsToAttributes, err := s.dbClient.GetAttributesByValueFqns(ctx, req)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("fqns", fmt.Sprintf("%v", req.GetFqns())))
	}
	rsp.FqnAttributeValues = fqnsToAttributes

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
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", attributeID))
	}

	updated, err := s.dbClient.UpdateAttribute(ctx, req.GetId(), req)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()), slog.String("attribute", req.String()))
	}

	auditParams.Original = original
	auditParams.Updated = updated
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.Attribute = updated
	return rsp, nil
}

func (s *AttributesService) DeactivateAttribute(ctx context.Context,
	req *attributes.DeactivateAttributeRequest,
) (*attributes.DeactivateAttributeResponse, error) {
	rsp := &attributes.DeactivateAttributeResponse{}

	attributeID := req.GetId()

	auditParams := audit.PolicyEventParams{
		ObjectType: audit.ObjectTypeAttributeDefinition,
		ActionType: audit.ActionTypeDelete,
		ObjectID:   attributeID,
	}

	a, err := s.dbClient.DeactivateAttribute(ctx, attributeID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeactivationFailed, slog.String("id", attributeID))
	}
	rsp.Attribute = a

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	return rsp, nil
}

///
/// Attribute Values
///

func (s *AttributesService) CreateAttributeValue(ctx context.Context, req *attributes.CreateAttributeValueRequest) (*attributes.CreateAttributeValueResponse, error) {
	auditParams := audit.PolicyEventParams{
		ObjectType: audit.ObjectTypeAttributeValue,
		ActionType: audit.ActionTypeCreate,
	}

	item, err := s.dbClient.CreateAttributeValue(ctx, req.GetAttributeId(), req)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("attributeId", req.GetAttributeId()), slog.String("value", req.String()))
	}

	auditParams.ObjectID = item.GetId()
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	return &attributes.CreateAttributeValueResponse{
		Value: item,
	}, nil
}

func (s *AttributesService) ListAttributeValues(ctx context.Context, req *attributes.ListAttributeValuesRequest) (*attributes.ListAttributeValuesResponse, error) {
	state := policydb.GetDBStateTypeTransformedEnum(req.GetState())
	s.logger.Debug("listing attribute values", slog.String("attributeId", req.GetAttributeId()), slog.String("state", state))
	list, err := s.dbClient.ListAttributeValues(ctx, req.GetAttributeId(), state)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed, slog.String("attributeId", req.GetAttributeId()))
	}

	return &attributes.ListAttributeValuesResponse{
		Values: list,
	}, nil
}

func (s *AttributesService) GetAttributeValue(ctx context.Context, req *attributes.GetAttributeValueRequest) (*attributes.GetAttributeValueResponse, error) {
	item, err := s.dbClient.GetAttributeValue(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}

	return &attributes.GetAttributeValueResponse{
		Value: item,
	}, nil
}

func (s *AttributesService) UpdateAttributeValue(ctx context.Context, req *attributes.UpdateAttributeValueRequest) (*attributes.UpdateAttributeValueResponse, error) {
	a, err := s.dbClient.UpdateAttributeValue(ctx, req)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()), slog.String("value", req.String()))
	}

	return &attributes.UpdateAttributeValueResponse{
		Value: a,
	}, nil
}

func (s *AttributesService) DeactivateAttributeValue(ctx context.Context, req *attributes.DeactivateAttributeValueRequest) (*attributes.DeactivateAttributeValueResponse, error) {
	attributeID := req.GetId()

	auditParams := audit.PolicyEventParams{
		ObjectType: audit.ObjectTypeAttributeValue,
		ActionType: audit.ActionTypeDelete,
		ObjectID:   attributeID,
	}

	a, err := s.dbClient.DeactivateAttributeValue(ctx, attributeID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeactivationFailed, slog.String("id", attributeID))
	}

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	return &attributes.DeactivateAttributeValueResponse{
		Value: a,
	}, nil
}

func (s *AttributesService) AssignKeyAccessServerToAttribute(ctx context.Context, req *attributes.AssignKeyAccessServerToAttributeRequest) (*attributes.AssignKeyAccessServerToAttributeResponse, error) {
	attributeKas, err := s.dbClient.AssignKeyAccessServerToAttribute(ctx, req.GetAttributeKeyAccessServer())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("attributeKas", req.GetAttributeKeyAccessServer().String()))
	}

	return &attributes.AssignKeyAccessServerToAttributeResponse{
		AttributeKeyAccessServer: attributeKas,
	}, nil
}

func (s *AttributesService) RemoveKeyAccessServerFromAttribute(ctx context.Context, req *attributes.RemoveKeyAccessServerFromAttributeRequest) (*attributes.RemoveKeyAccessServerFromAttributeResponse, error) {
	attributeKas, err := s.dbClient.RemoveKeyAccessServerFromAttribute(ctx, req.GetAttributeKeyAccessServer())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("attributeKas", req.GetAttributeKeyAccessServer().String()))
	}

	return &attributes.RemoveKeyAccessServerFromAttributeResponse{
		AttributeKeyAccessServer: attributeKas,
	}, nil
}

func (s *AttributesService) AssignKeyAccessServerToValue(ctx context.Context, req *attributes.AssignKeyAccessServerToValueRequest) (*attributes.AssignKeyAccessServerToValueResponse, error) {
	valueKas, err := s.dbClient.AssignKeyAccessServerToValue(ctx, req.GetValueKeyAccessServer())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("attributeValueKas", req.GetValueKeyAccessServer().String()))
	}

	return &attributes.AssignKeyAccessServerToValueResponse{
		ValueKeyAccessServer: valueKas,
	}, nil
}

func (s *AttributesService) RemoveKeyAccessServerFromValue(ctx context.Context, req *attributes.RemoveKeyAccessServerFromValueRequest) (*attributes.RemoveKeyAccessServerFromValueResponse, error) {
	valueKas, err := s.dbClient.RemoveKeyAccessServerFromValue(ctx, req.GetValueKeyAccessServer())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("attributeValueKas", req.GetValueKeyAccessServer().String()))
	}

	return &attributes.RemoveKeyAccessServerFromValueResponse{
		ValueKeyAccessServer: valueKas,
	}, nil
}
