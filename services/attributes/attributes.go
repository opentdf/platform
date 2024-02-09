package attributes

import (
	"context"
	"errors"
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
	req *attributes.CreateAttributeRequest,
) (*attributes.CreateAttributeResponse, error) {
	slog.Debug("creating new attribute definition", slog.String("name", req.Attribute.Name))
	rsp := &attributes.CreateAttributeResponse{}

	item, err := s.dbClient.CreateAttribute(ctx, req.Attribute)
	if err != nil {
		if errors.Is(err, db.ErrUniqueConstraintViolation) {
			slog.Error(services.ErrConflict, slog.String("error", err.Error()), slog.String("attribute", req.Attribute.String()))
			return nil, status.Error(codes.AlreadyExists, services.ErrConflict)
		}
		if errors.Is(err, db.ErrForeignKeyViolation) {
			slog.Error(services.ErrRelationInvalid, slog.String("error", err.Error()), slog.String("attribute", req.Attribute.String()))
			return nil, status.Error(codes.InvalidArgument, services.ErrRelationInvalid)
		}
		if errors.Is(err, db.ErrEnumValueInvalid) {
			slog.Error(services.ErrEnumValueInvalid, slog.String("error", err.Error()), slog.String("rule", req.Attribute.Rule.String()))
			return nil, status.Error(codes.InvalidArgument, services.ErrEnumValueInvalid)
		}
		slog.Error(services.ErrCreationFailed, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrCreationFailed)
	}
	rsp.Attribute = item

	slog.Debug("created new attribute definition", slog.String("name", req.Attribute.Name))
	return rsp, nil
}

func (s *AttributesService) ListAttributes(ctx context.Context,
	req *attributes.ListAttributesRequest,
) (*attributes.ListAttributesResponse, error) {
	rsp := &attributes.ListAttributesResponse{}

	list, err := s.dbClient.ListAllAttributes(ctx)
	if err != nil {
		slog.Error(services.ErrListRetrievalFailed, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrListRetrievalFailed)
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
		if errors.Is(err, db.ErrNotFound) {
			slog.Error(services.ErrNotFound, slog.String("error", err.Error()), slog.String("id", req.Id))
			return nil, status.Error(codes.NotFound, services.ErrNotFound)
		}
		slog.Error(services.ErrGetRetrievalFailed, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrGetRetrievalFailed)
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
		if errors.Is(err, db.ErrUniqueConstraintViolation) {
			slog.Error(services.ErrConflict, slog.String("error", err.Error()), slog.String("id", req.Id), slog.String("attribute", req.Attribute.String()))
			return nil, status.Error(codes.AlreadyExists, services.ErrConflict)
		}
		if errors.Is(err, db.ErrNotFound) {
			slog.Error(services.ErrNotFound, slog.String("error", err.Error()), slog.String("id", req.Id))
			return nil, status.Error(codes.NotFound, services.ErrNotFound)
		}
		if errors.Is(err, db.ErrForeignKeyViolation) {
			slog.Error(services.ErrRelationInvalid, slog.String("error", err.Error()), slog.String("id", req.Id), slog.String("attribute", req.Attribute.String()))
			return nil, status.Error(codes.InvalidArgument, services.ErrRelationInvalid)
		}
		if errors.Is(err, db.ErrEnumValueInvalid) {
			slog.Error(services.ErrEnumValueInvalid, slog.String("error", err.Error()), slog.String("rule", req.Attribute.Rule.String()))
			return nil, status.Error(codes.InvalidArgument, services.ErrEnumValueInvalid)
		}
		slog.Error(services.ErrUpdateFailed, slog.String("error", err.Error()))
		return &attributes.UpdateAttributeResponse{},
			status.Error(codes.Internal, services.ErrUpdateFailed)
	}
	rsp.Attribute = a

	return rsp, nil
}

func (s *AttributesService) DeleteAttribute(ctx context.Context,
	req *attributes.DeleteAttributeRequest,
) (*attributes.DeleteAttributeResponse, error) {
	rsp := &attributes.DeleteAttributeResponse{}

	a, err := s.dbClient.DeleteAttribute(ctx, req.Id)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			slog.Error(services.ErrNotFound, slog.String("error", err.Error()), slog.String("id", req.Id))
			return nil, status.Error(codes.NotFound, services.ErrNotFound)
		}
		slog.Error(services.ErrDeletionFailed, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrDeletionFailed)
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
		if errors.Is(err, db.ErrUniqueConstraintViolation) {
			slog.Error(services.ErrConflict, slog.String("error", err.Error()), slog.String("attribute value", req.Value.String()), slog.String("attribute id", req.AttributeId))
			return nil, status.Error(codes.AlreadyExists, services.ErrConflict)
		}
		if errors.Is(err, db.ErrForeignKeyViolation) {
			slog.Error(services.ErrRelationInvalid, slog.String("error", err.Error()), slog.String("attribute value", req.Value.String()), slog.String("attribute id", req.AttributeId))
			return nil, status.Error(codes.InvalidArgument, services.ErrRelationInvalid)
		}
		slog.Error(services.ErrCreationFailed, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrCreationFailed)
	}

	return &attributes.CreateAttributeValueResponse{
		Value: item,
	}, nil
}

func (s *AttributesService) ListAttributeValues(ctx context.Context, req *attributes.ListAttributeValuesRequest) (*attributes.ListAttributeValuesResponse, error) {
	list, err := s.dbClient.ListAttributeValues(ctx, req.AttributeId)
	if err != nil {
		slog.Error(services.ErrListRetrievalFailed, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrListRetrievalFailed)
	}

	return &attributes.ListAttributeValuesResponse{
		Values: list,
	}, nil
}

func (s *AttributesService) GetAttributeValue(ctx context.Context, req *attributes.GetAttributeValueRequest) (*attributes.GetAttributeValueResponse, error) {
	item, err := s.dbClient.GetAttributeValue(ctx, req.Id)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			slog.Error(services.ErrNotFound, slog.String("error", err.Error()), slog.String("id", req.Id))
			return nil, status.Error(codes.NotFound, services.ErrNotFound)
		}
		slog.Error(services.ErrGetRetrievalFailed, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrGetRetrievalFailed)
	}

	return &attributes.GetAttributeValueResponse{
		Value: item,
	}, nil
}

func (s *AttributesService) UpdateAttributeValue(ctx context.Context, req *attributes.UpdateAttributeValueRequest) (*attributes.UpdateAttributeValueResponse, error) {
	a, err := s.dbClient.UpdateAttributeValue(ctx, req.Id, req.Value)
	if err != nil {
		if errors.Is(err, db.ErrUniqueConstraintViolation) {
			slog.Error(services.ErrConflict, slog.String("error", err.Error()), slog.String("id", req.Id), slog.String("value", req.Value.String()), slog.String("attributeId", req.AttributeId))
			return nil, status.Error(codes.AlreadyExists, services.ErrConflict)
		}
		if errors.Is(err, db.ErrNotFound) {
			slog.Error(services.ErrNotFound, slog.String("error", err.Error()), slog.String("id", req.Id))
			return nil, status.Error(codes.NotFound, services.ErrNotFound)
		}
		if errors.Is(err, db.ErrForeignKeyViolation) {
			slog.Error(services.ErrRelationInvalid, slog.String("error", err.Error()), slog.String("value", req.Value.String()), slog.String("attributeId", req.AttributeId))
			return nil, status.Error(codes.InvalidArgument, services.ErrRelationInvalid)
		}
		slog.Error(services.ErrUpdateFailed, slog.String("error", err.Error()))
		return nil,
			status.Error(codes.Internal, services.ErrUpdateFailed)
	}

	return &attributes.UpdateAttributeValueResponse{
		Value: a,
	}, nil
}

func (s *AttributesService) DeleteAttributeValue(ctx context.Context, req *attributes.DeleteAttributeValueRequest) (*attributes.DeleteAttributeValueResponse, error) {
	a, err := s.dbClient.DeleteAttributeValue(ctx, req.Id)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			slog.Error(services.ErrNotFound, slog.String("error", err.Error()), slog.String("id", req.Id))
			return nil, status.Error(codes.NotFound, services.ErrNotFound)
		}
		slog.Error(services.ErrDeletionFailed, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrDeletionFailed)
	}

	return &attributes.DeleteAttributeValueResponse{
		Value: a,
	}, nil
}

func (s *AttributesService) AssignKeyAccessServerToAttribute(ctx context.Context, req *attributes.AssignKeyAccessServerToAttributeRequest) (*attributes.AssignKeyAccessServerToAttributeResponse, error) {
	attributeKas, err := s.dbClient.AssignKeyAccessServerToAttribute(ctx, req.AttributeKeyAccessServer)
	if err != nil {
		if errors.Is(err, db.ErrUniqueConstraintViolation) {
			slog.Error(services.ErrConflict, slog.String("error", err.Error()), slog.String("attributeKas", req.AttributeKeyAccessServer.String()))
			return nil, status.Error(codes.AlreadyExists, services.ErrConflict)
		}
		if errors.Is(err, db.ErrForeignKeyViolation) {
			slog.Error(services.ErrRelationInvalid, slog.String("error", err.Error()), slog.String("attributeKas", req.AttributeKeyAccessServer.String()))
			return nil, status.Error(codes.InvalidArgument, services.ErrRelationInvalid)
		}
		slog.Error(services.ErrUpdateFailed, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrUpdateFailed)
	}

	return &attributes.AssignKeyAccessServerToAttributeResponse{
		AttributeKeyAccessServer: attributeKas,
	}, nil
}

func (s *AttributesService) RemoveKeyAccessServerFromAttribute(ctx context.Context, req *attributes.RemoveKeyAccessServerFromAttributeRequest) (*attributes.RemoveKeyAccessServerFromAttributeResponse, error) {
	attributeKas, err := s.dbClient.RemoveKeyAccessServerFromAttribute(ctx, req.AttributeKeyAccessServer)
	if err != nil {
		if errors.Is(err, db.ErrUniqueConstraintViolation) {
			slog.Error(services.ErrConflict, slog.String("error", err.Error()), slog.String("attributeKas", req.AttributeKeyAccessServer.String()))
			return nil, status.Error(codes.AlreadyExists, services.ErrConflict)
		}
		if errors.Is(err, db.ErrForeignKeyViolation) {
			slog.Error(services.ErrRelationInvalid, slog.String("error", err.Error()), slog.String("attributeKas", req.AttributeKeyAccessServer.String()))
			return nil, status.Error(codes.InvalidArgument, services.ErrRelationInvalid)
		}
		slog.Error(services.ErrUpdateFailed, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrUpdateFailed)
	}

	return &attributes.RemoveKeyAccessServerFromAttributeResponse{
		AttributeKeyAccessServer: attributeKas,
	}, nil
}

func (s *AttributesService) AssignKeyAccessServerToValue(ctx context.Context, req *attributes.AssignKeyAccessServerToValueRequest) (*attributes.AssignKeyAccessServerToValueResponse, error) {
	valueKas, err := s.dbClient.AssignKeyAccessServerToValue(ctx, req.ValueKeyAccessServer)
	if err != nil {
		if errors.Is(err, db.ErrUniqueConstraintViolation) {
			slog.Error(services.ErrConflict, slog.String("error", err.Error()), slog.String("valueKas", req.ValueKeyAccessServer.String()))
			return nil, status.Error(codes.AlreadyExists, services.ErrConflict)
		}
		if errors.Is(err, db.ErrForeignKeyViolation) {
			slog.Error(services.ErrRelationInvalid, slog.String("error", err.Error()), slog.String("valueKas", req.ValueKeyAccessServer.String()))
			return nil, status.Error(codes.InvalidArgument, services.ErrRelationInvalid)
		}
		slog.Error(services.ErrUpdateFailed, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrUpdateFailed)
	}

	return &attributes.AssignKeyAccessServerToValueResponse{
		ValueKeyAccessServer: valueKas,
	}, nil
}

func (s *AttributesService) RemoveKeyAccessServerFromValue(ctx context.Context, req *attributes.RemoveKeyAccessServerFromValueRequest) (*attributes.RemoveKeyAccessServerFromValueResponse, error) {
	valueKas, err := s.dbClient.RemoveKeyAccessServerFromValue(ctx, req.ValueKeyAccessServer)
	if err != nil {
		if errors.Is(err, db.ErrUniqueConstraintViolation) {
			slog.Error(services.ErrConflict, slog.String("error", err.Error()), slog.String("valueKas", req.ValueKeyAccessServer.String()))
			return nil, status.Error(codes.AlreadyExists, services.ErrConflict)
		}
		if errors.Is(err, db.ErrForeignKeyViolation) {
			slog.Error(services.ErrRelationInvalid, slog.String("error", err.Error()), slog.String("valueKas", req.ValueKeyAccessServer.String()))
			return nil, status.Error(codes.InvalidArgument, services.ErrRelationInvalid)
		}
		slog.Error(services.ErrUpdateFailed, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrUpdateFailed)
	}

	return &attributes.RemoveKeyAccessServerFromValueResponse{
		ValueKeyAccessServer: valueKas,
	}, nil
}
