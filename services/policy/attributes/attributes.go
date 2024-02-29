package attributes

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/internal/db"
	attr "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/services"
	policydb "github.com/opentdf/platform/services/policy/db"
	"google.golang.org/grpc"
)

type AttributesService struct {
	attr.UnimplementedAttributesServiceServer
	dbClient *policydb.PolicyDbClient
}

func NewAttributesServer(dbClient *db.Client, g *grpc.Server, grpcInprocess *grpc.Server, s *runtime.ServeMux) error {
	as := &AttributesService{
		dbClient: policydb.NewClient(*dbClient),
	}
	attr.RegisterAttributesServiceServer(g, as)
	if grpcInprocess != nil {
		attr.RegisterAttributesServiceServer(grpcInprocess, as)
	}
	err := attr.RegisterAttributesServiceHandlerServer(context.Background(), s, as)
	if err != nil {
		return fmt.Errorf("failed to register attributes service handler: %w", err)
	}
	return nil
}

func (s AttributesService) CreateAttribute(ctx context.Context,
	req *attr.CreateAttributeRequest,
) (*attr.CreateAttributeResponse, error) {
	slog.Debug("creating new attribute definition", slog.String("name", req.Attribute.Name))
	rsp := &attr.CreateAttributeResponse{}

	item, err := s.dbClient.CreateAttribute(ctx, req.Attribute)
	if err != nil {
		return nil, services.HandleError(err, services.ErrCreationFailed, slog.String("attribute", req.Attribute.String()))
	}
	rsp.Attribute = item

	slog.Debug("created new attribute definition", slog.String("name", req.Attribute.Name))
	return rsp, nil
}

func (s *AttributesService) ListAttributes(ctx context.Context,
	req *attr.ListAttributesRequest,
) (*attr.ListAttributesResponse, error) {
	state := services.GetDbStateTypeTransformedEnum(req.State)
	slog.Debug("listing attribute definitions", slog.String("state", state))
	rsp := &attr.ListAttributesResponse{}

	list, err := s.dbClient.ListAllAttributes(ctx, state)
	if err != nil {
		return nil, services.HandleError(err, services.ErrListRetrievalFailed)
	}
	rsp.Attributes = list

	return rsp, nil
}

func (s *AttributesService) GetAttribute(ctx context.Context,
	req *attr.GetAttributeRequest,
) (*attr.GetAttributeResponse, error) {
	rsp := &attr.GetAttributeResponse{}

	item, err := s.dbClient.GetAttribute(ctx, req.Id)
	if err != nil {
		return nil, services.HandleError(err, services.ErrGetRetrievalFailed, slog.String("id", req.Id))
	}
	rsp.Attribute = item

	return rsp, err
}

func (s *AttributesService) GetAttributesByValueFqns(ctx context.Context,
	req *attr.GetAttributesByValueFqnsRequest,
) (*attr.GetAttributesByValueFqnsResponse, error) {
	rsp := &attr.GetAttributesByValueFqnsResponse{}

	fqnsToAttributes, err := s.dbClient.GetAttributesByValueFqns(ctx, req.Fqns)
	if err != nil {
		return nil, services.HandleError(err, services.ErrGetRetrievalFailed, slog.String("fqns", fmt.Sprintf("%v", req.Fqns)))
	}
	rsp.FqnAttributeValues = fqnsToAttributes

	return rsp, nil
}

func (s *AttributesService) UpdateAttribute(ctx context.Context,
	req *attr.UpdateAttributeRequest,
) (*attr.UpdateAttributeResponse, error) {
	rsp := &attr.UpdateAttributeResponse{}

	a, err := s.dbClient.UpdateAttribute(ctx, req.Id, req.Attribute)
	if err != nil {
		return nil, services.HandleError(err, services.ErrUpdateFailed, slog.String("id", req.Id), slog.String("attribute", req.Attribute.String()))
	}
	rsp.Attribute = a

	return rsp, nil
}

func (s *AttributesService) DeactivateAttribute(ctx context.Context,
	req *attr.DeactivateAttributeRequest,
) (*attr.DeactivateAttributeResponse, error) {
	rsp := &attr.DeactivateAttributeResponse{}

	a, err := s.dbClient.DeactivateAttribute(ctx, req.Id)
	if err != nil {
		return nil, services.HandleError(err, services.ErrDeactivationFailed, slog.String("id", req.Id))
	}
	rsp.Attribute = a

	return rsp, nil
}

///
/// Attribute Values
///

func (s *AttributesService) CreateAttributeValue(ctx context.Context, req *attr.CreateAttributeValueRequest) (*attr.CreateAttributeValueResponse, error) {
	item, err := s.dbClient.CreateAttributeValue(ctx, req.AttributeId, req.Value)
	if err != nil {
		return nil, services.HandleError(err, services.ErrCreationFailed, slog.String("attributeId", req.AttributeId), slog.String("value", req.Value.String()))
	}

	return &attr.CreateAttributeValueResponse{
		Value: item,
	}, nil
}

func (s *AttributesService) ListAttributeValues(ctx context.Context, req *attr.ListAttributeValuesRequest) (*attr.ListAttributeValuesResponse, error) {
	state := services.GetDbStateTypeTransformedEnum(req.State)
	slog.Debug("listing attribute values", slog.String("attributeId", req.AttributeId), slog.String("state", state))
	list, err := s.dbClient.ListAttributeValues(ctx, req.AttributeId, state)
	if err != nil {
		return nil, services.HandleError(err, services.ErrListRetrievalFailed, slog.String("attributeId", req.AttributeId))
	}

	return &attr.ListAttributeValuesResponse{
		Values: list,
	}, nil
}

func (s *AttributesService) GetAttributeValue(ctx context.Context, req *attr.GetAttributeValueRequest) (*attr.GetAttributeValueResponse, error) {
	item, err := s.dbClient.GetAttributeValue(ctx, req.Id)
	if err != nil {
		return nil, services.HandleError(err, services.ErrGetRetrievalFailed, slog.String("id", req.Id))
	}

	return &attr.GetAttributeValueResponse{
		Value: item,
	}, nil
}

func (s *AttributesService) UpdateAttributeValue(ctx context.Context, req *attr.UpdateAttributeValueRequest) (*attr.UpdateAttributeValueResponse, error) {
	a, err := s.dbClient.UpdateAttributeValue(ctx, req.Id, req.Value)
	if err != nil {
		return nil, services.HandleError(err, services.ErrUpdateFailed, slog.String("id", req.Id), slog.String("value", req.Value.String()))
	}

	return &attr.UpdateAttributeValueResponse{
		Value: a,
	}, nil
}

func (s *AttributesService) DeactivateAttributeValue(ctx context.Context, req *attr.DeactivateAttributeValueRequest) (*attr.DeactivateAttributeValueResponse, error) {
	a, err := s.dbClient.DeactivateAttributeValue(ctx, req.Id)
	if err != nil {
		return nil, services.HandleError(err, services.ErrDeactivationFailed, slog.String("id", req.Id))
	}

	return &attr.DeactivateAttributeValueResponse{
		Value: a,
	}, nil
}

func (s *AttributesService) AssignKeyAccessServerToAttribute(ctx context.Context, req *attr.AssignKeyAccessServerToAttributeRequest) (*attr.AssignKeyAccessServerToAttributeResponse, error) {
	attributeKas, err := s.dbClient.AssignKeyAccessServerToAttribute(ctx, req.AttributeKeyAccessServer)
	if err != nil {
		return nil, services.HandleError(err, services.ErrCreationFailed, slog.String("attributeKas", req.AttributeKeyAccessServer.String()))
	}

	return &attr.AssignKeyAccessServerToAttributeResponse{
		AttributeKeyAccessServer: attributeKas,
	}, nil
}

func (s *AttributesService) RemoveKeyAccessServerFromAttribute(ctx context.Context, req *attr.RemoveKeyAccessServerFromAttributeRequest) (*attr.RemoveKeyAccessServerFromAttributeResponse, error) {
	attributeKas, err := s.dbClient.RemoveKeyAccessServerFromAttribute(ctx, req.AttributeKeyAccessServer)
	if err != nil {
		return nil, services.HandleError(err, services.ErrUpdateFailed, slog.String("attributeKas", req.AttributeKeyAccessServer.String()))
	}

	return &attr.RemoveKeyAccessServerFromAttributeResponse{
		AttributeKeyAccessServer: attributeKas,
	}, nil
}

func (s *AttributesService) AssignKeyAccessServerToValue(ctx context.Context, req *attr.AssignKeyAccessServerToValueRequest) (*attr.AssignKeyAccessServerToValueResponse, error) {
	valueKas, err := s.dbClient.AssignKeyAccessServerToValue(ctx, req.ValueKeyAccessServer)
	if err != nil {
		return nil, services.HandleError(err, services.ErrCreationFailed, slog.String("attributeValueKas", req.ValueKeyAccessServer.String()))
	}

	return &attr.AssignKeyAccessServerToValueResponse{
		ValueKeyAccessServer: valueKas,
	}, nil
}

func (s *AttributesService) RemoveKeyAccessServerFromValue(ctx context.Context, req *attr.RemoveKeyAccessServerFromValueRequest) (*attr.RemoveKeyAccessServerFromValueResponse, error) {
	valueKas, err := s.dbClient.RemoveKeyAccessServerFromValue(ctx, req.ValueKeyAccessServer)
	if err != nil {
		return nil, services.HandleError(err, services.ErrUpdateFailed, slog.String("attributeValueKas", req.ValueKeyAccessServer.String()))
	}

	return &attr.RemoveKeyAccessServerFromValueResponse{
		ValueKeyAccessServer: valueKas,
	}, nil
}
