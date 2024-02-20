package attributes

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/sdk/attributes"
	"github.com/opentdf/platform/services"
	"google.golang.org/grpc"
)

type AttributesService struct {
	attributes.UnimplementedAttributesServiceServer
	dbClient *db.Client
}

func NewAttributesServer(dbClient *db.Client, g *grpc.Server, s *runtime.ServeMux) error {
	as := &AttributesService{
		dbClient: dbClient,
	}
	attributes.RegisterAttributesServiceServer(g, as)
	err := attributes.RegisterAttributesServiceHandlerServer(context.Background(), s, as)
	if err != nil {
		return fmt.Errorf("failed to register attributes service handler: %w", err)
	}
	return nil
}

func (s AttributesService) CreateAttribute(ctx context.Context,
	req *attributes.CreateAttributeRequest,
) (*attributes.CreateAttributeResponse, error) {
	slog.Debug("creating new attribute definition", slog.String("name", req.Attribute.Name))
	rsp := &attributes.CreateAttributeResponse{}

	item, err := s.dbClient.CreateAttribute(ctx, req.Attribute)
	if err != nil {
		return nil, services.HandleError(err, services.ErrCreationFailed, slog.String("attribute", req.Attribute.String()))
	}
	rsp.Attribute = item

	slog.Debug("created new attribute definition", slog.String("name", req.Attribute.Name))
	return rsp, nil
}

func (s *AttributesService) ListAttributes(ctx context.Context,
	req *attributes.ListAttributesRequest,
) (*attributes.ListAttributesResponse, error) {
	state := services.GetDbStateTypeTransformedEnum(req.State)
	slog.Debug("listing attribute definitions", slog.String("state", state))
	rsp := &attributes.ListAttributesResponse{}

	list, err := s.dbClient.ListAllAttributes(ctx, state)
	if err != nil {
		return nil, services.HandleError(err, services.ErrListRetrievalFailed)
	}
	rsp.Attributes = list

	return rsp, nil
}

//nolint:dupl // there probably is duplication in these crud operations but its not worth refactoring yet.
func (s *AttributesService) GetAttribute(ctx context.Context,
	req *attributes.GetAttributeRequest,
) (*attributes.GetAttributeResponse, error) {
	rsp := &attributes.GetAttributeResponse{}

	item, err := s.dbClient.GetAttribute(ctx, req.Id)
	if err != nil {
		return nil, services.HandleError(err, services.ErrGetRetrievalFailed, slog.String("id", req.Id))
	}
	rsp.Attribute = item

	return rsp, err
}

func (s *AttributesService) UpdateAttribute(ctx context.Context,
	req *attributes.UpdateAttributeRequest,
) (*attributes.UpdateAttributeResponse, error) {
	rsp := &attributes.UpdateAttributeResponse{}

	a, err := s.dbClient.UpdateAttribute(ctx, req.Id, req.Attribute)
	if err != nil {
		return nil, services.HandleError(err, services.ErrUpdateFailed, slog.String("id", req.Id), slog.String("attribute", req.Attribute.String()))
	}
	rsp.Attribute = a

	return rsp, nil
}

func (s *AttributesService) DeactivateAttribute(ctx context.Context,
	req *attributes.DeactivateAttributeRequest,
) (*attributes.DeactivateAttributeResponse, error) {
	rsp := &attributes.DeactivateAttributeResponse{}

	a, err := s.dbClient.DeactivateAttribute(ctx, req.Id)
	if err != nil {
		return nil, services.HandleError(err, services.ErrDeletionFailed, slog.String("id", req.Id))
	}
	rsp.Attribute = a

	return rsp, nil
}

///
/// Attribute Values
///

func (s *AttributesService) CreateAttributeValue(ctx context.Context, req *attributes.CreateAttributeValueRequest) (*attributes.CreateAttributeValueResponse, error) {
	item, err := s.dbClient.CreateAttributeValue(ctx, req.AttributeId, req.Value)
	if err != nil {
		return nil, services.HandleError(err, services.ErrCreationFailed, slog.String("attributeId", req.AttributeId), slog.String("value", req.Value.String()))
	}

	return &attributes.CreateAttributeValueResponse{
		Value: item,
	}, nil
}

func (s *AttributesService) ListAttributeValues(ctx context.Context, req *attributes.ListAttributeValuesRequest) (*attributes.ListAttributeValuesResponse, error) {
	state := services.GetDbStateTypeTransformedEnum(req.State)
	slog.Debug("listing attribute values", slog.String("attributeId", req.AttributeId), slog.String("state", state))
	list, err := s.dbClient.ListAttributeValues(ctx, req.AttributeId, state)
	if err != nil {
		return nil, services.HandleError(err, services.ErrListRetrievalFailed, slog.String("attributeId", req.AttributeId))
	}

	return &attributes.ListAttributeValuesResponse{
		Values: list,
	}, nil
}

func (s *AttributesService) GetAttributeValue(ctx context.Context, req *attributes.GetAttributeValueRequest) (*attributes.GetAttributeValueResponse, error) {
	item, err := s.dbClient.GetAttributeValue(ctx, req.Id)
	if err != nil {
		return nil, services.HandleError(err, services.ErrGetRetrievalFailed, slog.String("id", req.Id))
	}

	return &attributes.GetAttributeValueResponse{
		Value: item,
	}, nil
}

func (s *AttributesService) UpdateAttributeValue(ctx context.Context, req *attributes.UpdateAttributeValueRequest) (*attributes.UpdateAttributeValueResponse, error) {
	a, err := s.dbClient.UpdateAttributeValue(ctx, req.Id, req.Value)
	if err != nil {
		return nil, services.HandleError(err, services.ErrUpdateFailed, slog.String("id", req.Id), slog.String("value", req.Value.String()))
	}

	return &attributes.UpdateAttributeValueResponse{
		Value: a,
	}, nil
}

func (s *AttributesService) DeactivateAttributeValue(ctx context.Context, req *attributes.DeactivateAttributeValueRequest) (*attributes.DeactivateAttributeValueResponse, error) {
	a, err := s.dbClient.DeactivateAttributeValue(ctx, req.Id)
	if err != nil {
		return nil, services.HandleError(err, services.ErrDeletionFailed, slog.String("id", req.Id))
	}

	return &attributes.DeactivateAttributeValueResponse{
		Value: a,
	}, nil
}

func (s *AttributesService) AssignKeyAccessServerToAttribute(ctx context.Context, req *attributes.AssignKeyAccessServerToAttributeRequest) (*attributes.AssignKeyAccessServerToAttributeResponse, error) {
	attributeKas, err := s.dbClient.AssignKeyAccessServerToAttribute(ctx, req.AttributeKeyAccessServer)
	if err != nil {
		return nil, services.HandleError(err, services.ErrCreationFailed, slog.String("attributeKas", req.AttributeKeyAccessServer.String()))
	}

	return &attributes.AssignKeyAccessServerToAttributeResponse{
		AttributeKeyAccessServer: attributeKas,
	}, nil
}

func (s *AttributesService) RemoveKeyAccessServerFromAttribute(ctx context.Context, req *attributes.RemoveKeyAccessServerFromAttributeRequest) (*attributes.RemoveKeyAccessServerFromAttributeResponse, error) {
	attributeKas, err := s.dbClient.RemoveKeyAccessServerFromAttribute(ctx, req.AttributeKeyAccessServer)
	if err != nil {
		return nil, services.HandleError(err, services.ErrUpdateFailed, slog.String("attributeKas", req.AttributeKeyAccessServer.String()))
	}

	return &attributes.RemoveKeyAccessServerFromAttributeResponse{
		AttributeKeyAccessServer: attributeKas,
	}, nil
}

func (s *AttributesService) AssignKeyAccessServerToValue(ctx context.Context, req *attributes.AssignKeyAccessServerToValueRequest) (*attributes.AssignKeyAccessServerToValueResponse, error) {
	valueKas, err := s.dbClient.AssignKeyAccessServerToValue(ctx, req.ValueKeyAccessServer)
	if err != nil {
		return nil, services.HandleError(err, services.ErrCreationFailed, slog.String("attributeValueKas", req.ValueKeyAccessServer.String()))
	}

	return &attributes.AssignKeyAccessServerToValueResponse{
		ValueKeyAccessServer: valueKas,
	}, nil
}

func (s *AttributesService) RemoveKeyAccessServerFromValue(ctx context.Context, req *attributes.RemoveKeyAccessServerFromValueRequest) (*attributes.RemoveKeyAccessServerFromValueResponse, error) {
	valueKas, err := s.dbClient.RemoveKeyAccessServerFromValue(ctx, req.ValueKeyAccessServer)
	if err != nil {
		return nil, services.HandleError(err, services.ErrUpdateFailed, slog.String("attributeValueKas", req.ValueKeyAccessServer.String()))
	}

	return &attributes.RemoveKeyAccessServerFromValueResponse{
		ValueKeyAccessServer: valueKas,
	}, nil
}
