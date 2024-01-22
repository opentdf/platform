package attributes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/sdk/attributes"
	"github.com/opentdf/opentdf-v2-poc/sdk/common"
	"github.com/opentdf/opentdf-v2-poc/services"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

type AttributesService struct {
	attributes.UnimplementedAttributesServiceServer
	dbClient *db.Client
}

func attributeRuleTypeEnumTransformer(rule string) attributes.AttributeRuleTypeEnum {
	rule = "ATTRIBUTE_RULE_TYPE_ENUM" + rule
	return attributes.AttributeRuleTypeEnum(attributes.AttributeRuleTypeEnum_value[rule])
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

	if err := s.dbClient.CreateAttribute(ctx, req.Attribute); err != nil {
		slog.Error(services.ErrCreatingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrCreatingResource)
	}

	slog.Debug("created new attribute definition", slog.String("name", req.Attribute.Name))
	return &attributes.CreateAttributeResponse{}, nil
}

func (s *AttributesService) ListAttributes(ctx context.Context,
	req *attributes.ListAttributesRequest) (*attributes.ListAttributesResponse, error) {
	attributesList := &attributes.ListAttributesResponse{}

	rows, err := s.dbClient.ListAllAttributes(ctx)
	if err != nil {
		slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrListingResource)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id       string
			name     string
			rule     string
			metadata []byte
			values   []byte
		)
		err = rows.Scan(&id, &name, &rule, &metadata, &values)
		if err != nil {
			slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
			return nil, status.Error(codes.Internal, services.ErrListingResource)
		}

		attribute := &attributes.Attribute{
			Id:   id,
			Name: name,
			Rule: attributeRuleTypeEnumTransformer(rule),
		}

		attributesList.Attributes = append(attributesList.Attributes, attribute)
	}

	if err := rows.Err(); err != nil {
		slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrListingResource)
	}

	return attributesList, nil
}

//nolint:dupl // there probably is duplication in these crud operations but its not worth refactoring yet.
func (s *AttributesService) GetAttribute(ctx context.Context,
	req *attributes.GetAttributeRequest) (*attributes.GetAttributeResponse, error) {
	var (
		id           string
		name         string
		rule         string
		metadataJson []byte
		valuesJson   []byte
	)

	row, err := s.dbClient.GetAttribute(
		ctx,
		req.Id,
	)
	if err != nil {
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrGettingResource)
	}

	err = row.Scan(&id, &name, &rule, &metadataJson, &valuesJson)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Info(services.ErrNotFound, slog.String("id", req.Id))
			return nil, status.Error(codes.NotFound, services.ErrNotFound)
		}
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrGettingResource)
	}

	var metadata common.PolicyMetadata
	if metadataJson != nil {
		if err := protojson.Unmarshal(metadataJson, &metadata); err != nil {
			slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
			return nil, status.Error(codes.Internal, services.ErrGettingResource)
		}
	}

	var raw []json.RawMessage
	if err := json.Unmarshal(valuesJson, &raw); err != nil {
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrGettingResource)
	}

	values := make([]*attributes.Value, 0)
	for _, r := range raw {
		value := attributes.Value{}
		if err := protojson.Unmarshal(r, &value); err != nil {
			slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
			return nil, status.Error(codes.Internal, services.ErrGettingResource)
		}
		values = append(values, &value)
	}

	attr := &attributes.Attribute{
		Id:       id,
		Name:     name,
		Rule:     attributeRuleTypeEnumTransformer(rule),
		Values:   values,
		Metadata: &metadata,
	}

	return &attributes.GetAttributeResponse{
		Attribute: attr,
	}, nil
}

func (s *AttributesService) UpdateAttribute(ctx context.Context,
	req *attributes.UpdateAttributeRequest) (*attributes.UpdateAttributeResponse, error) {
	if err := s.dbClient.UpdateAttribute(
		ctx,
		req.Id,
		req.Attribute,
	); err != nil {
		slog.Error(services.ErrUpdatingResource, slog.String("error", err.Error()))
		return &attributes.UpdateAttributeResponse{},
			status.Error(codes.Internal, services.ErrUpdatingResource)
	}
	return &attributes.UpdateAttributeResponse{}, nil
}

func (s *AttributesService) DeleteAttribute(ctx context.Context,
	req *attributes.DeleteAttributeRequest) (*attributes.DeleteAttributeResponse, error) {
	if err := s.dbClient.DeleteAttribute(
		ctx,
		req.Id,
	); err != nil {
		slog.Error(services.ErrDeletingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrDeletingResource)
	}

	return &attributes.DeleteAttributeResponse{}, nil
}
