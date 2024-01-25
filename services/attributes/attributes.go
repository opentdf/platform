package attributes

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/sdk/attributes"
	"github.com/opentdf/opentdf-v2-poc/services"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	req *attributes.CreateAttributeRequest) (*attributes.CreateAttributeResponse, error) {
	slog.Debug("creating new attribute definition", slog.String("name", req.Attribute.Name))
	rsp := &attributes.CreateAttributeResponse{}

	item, err := s.dbClient.CreateAttribute(ctx, req.Attribute)
	if err != nil {
		slog.Error(services.ErrCreatingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrCreatingResource)
	}
	rsp.Attribute = item

	slog.Debug("created new attribute definition", slog.String("name", req.Attribute.Name))
	return rsp, nil
}

func (s *AttributesService) ListAttributes(ctx context.Context,
	req *attributes.ListAttributesRequest) (*attributes.ListAttributesResponse, error) {
	rsp := &attributes.ListAttributesResponse{}

	list, err := s.dbClient.ListAllAttributes(ctx)
	if err != nil {
		slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrListingResource)
	}
	rsp.Attributes = list

	return rsp, nil
}

//nolint:dupl // there probably is duplication in these crud operations but its not worth refactoring yet.
func (s *AttributesService) GetAttribute(ctx context.Context,
	req *attributes.GetAttributeRequest) (*attributes.GetAttributeResponse, error) {
	rsp := &attributes.GetAttributeResponse{}

	item, err := s.dbClient.GetAttribute(ctx, req.Id)
	if err != nil {
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrGettingResource)
	}
	rsp.Attribute = item

	return rsp, err
}

func (s *AttributesService) UpdateAttribute(ctx context.Context,
	req *attributes.UpdateAttributeRequest) (*attributes.UpdateAttributeResponse, error) {
	rsp := &attributes.UpdateAttributeResponse{}

	a, err := s.dbClient.UpdateAttribute(ctx, req.Id, req.Attribute)
	if err != nil {
		slog.Error(services.ErrUpdatingResource, slog.String("error", err.Error()))
		return &attributes.UpdateAttributeResponse{},
			status.Error(codes.Internal, services.ErrUpdatingResource)
	}
	rsp.Attribute = a

	return rsp, nil
}

func (s *AttributesService) DeleteAttribute(ctx context.Context,
	req *attributes.DeleteAttributeRequest) (*attributes.DeleteAttributeResponse, error) {
	rsp := &attributes.DeleteAttributeResponse{}

	a, err := s.dbClient.DeleteAttribute(ctx, req.Id)
	if err != nil {
		slog.Error(services.ErrDeletingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrDeletingResource)
	}
	rsp.Attribute = a

	return rsp, nil
}

///
/// Attribute Values
///

func (s *AttributesService) CreateAttributeValue(ctx context.Context, req *attributes.CreateValueRequest) (*attributes.CreateValueResponse, error) {
	rsp := &attributes.CreateValueResponse{}

	item, err := s.dbClient.CreateAttributeValue(ctx, req.Value)
	if err != nil {
		slog.Error(services.ErrCreatingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrCreatingResource)
	}
	rsp.Value = item

	return rsp, nil
}

func (s *AttributesService) ListAttributeValues(ctx context.Context, req *attributes.ListValuesRequest) (*attributes.ListValuesResponse, error) {
	rsp := &attributes.ListValuesResponse{}

	list, err := s.dbClient.ListAttributeValues(ctx, req.AttributeId)
	if err != nil {
		slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrListingResource)
	}
	rsp.Values = list

	return rsp, nil
}

func (s *AttributesService) GetAttributeValue(ctx context.Context, req *attributes.GetValueRequest) (*attributes.GetValueResponse, error) {
	rsp := &attributes.GetValueResponse{}

	item, err := s.dbClient.GetAttributeValue(ctx, req.Id)
	if err != nil {
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrGettingResource)
	}
	rsp.Value = item

	return rsp, nil
}

func (s *AttributesService) UpdateAttributeValue(ctx context.Context, req *attributes.UpdateValueRequest) (*attributes.UpdateValueResponse, error) {
	rsp := &attributes.UpdateValueResponse{}

	a, err := s.dbClient.UpdateAttributeValue(ctx, req.Id, req.Value)
	if err != nil {
		slog.Error(services.ErrUpdatingResource, slog.String("error", err.Error()))
		return &attributes.UpdateValueResponse{},
			status.Error(codes.Internal, services.ErrUpdatingResource)
	}
	rsp.Value = a

	return rsp, nil
}

func (s *AttributesService) DeleteAttributeValue(ctx context.Context, req *attributes.DeleteValueRequest) (*attributes.DeleteValueResponse, error) {
	rsp := &attributes.DeleteValueResponse{}

	a, err := s.dbClient.DeleteAttributeValue(ctx, req.Id)
	if err != nil {
		slog.Error(services.ErrDeletingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrDeletingResource)
	}
	rsp.Value = a

	return rsp, nil
}
