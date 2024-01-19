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
)

type AttributesService struct {
	attributes.UnimplementedAttributesServiceServer
	dbClient *db.Client
}

func attributeRuleTypeEnumTransformer(rule string) attributes.AttributeRuleTypeEnum {
	rule = "ATTRIBUTE_RULE_TYPE_ENUM" + rule
	return attributes.AttributeRuleTypeEnum(attributes.AttributeRuleTypeEnum_value[rule])
}

func hydrateAttributeValuesFromJson(v []byte) (values []*attributes.Value, err error) {
	var data []struct {
		Id      string   `json:"id,omitempty"`
		Value   string   `json:"value,omitempty"`
		Members []string `json:"members,omitempty"`
	}

	if err = json.Unmarshal(v, &data); err != nil {
		return nil, err
	}

	for _, v := range data {
		values = append(values, &attributes.Value{
			Id:      v.Id,
			Value:   v.Value,
			Members: v.Members,
		})
	}

	return values, nil
}

func hydrateMetadataFromJson(m []byte) (metadata *common.PolicyMetadata, err error) {
	var data struct {
		CreatedAt   string            `json:"createdAt,omitempty"`
		UpdatedAt   string            `json:"updatedAt,omitempty"`
		Labels      map[string]string `json:"labels,omitempty"`
		Description string            `json:"description,omitempty"`
	}

	if err = json.Unmarshal(m, &data); err != nil {
		return nil, err
	}

	return &common.PolicyMetadata{
		Labels:      data.Labels,
		Description: data.Description,
	}, nil
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
		id         string
		name       string
		rule       string
		metadata   []byte
		valuesJson []byte
	)

	row, err := s.dbClient.GetAttribute(
		ctx,
		req.Id,
	)
	if err != nil {
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrGettingResource)
	}

	err = row.Scan(&id, &name, &rule, &metadata, &valuesJson)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Info(services.ErrNotFound, slog.String("id", req.Id))
			return nil, status.Error(codes.NotFound, services.ErrNotFound)
		}
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrGettingResource)
	}

	attrVals, err := hydrateAttributeValuesFromJson(valuesJson)
	if err != nil {
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrGettingResource)
	}

	attr := &attributes.Attribute{
		Id:     id,
		Name:   name,
		Rule:   attributeRuleTypeEnumTransformer(rule),
		Values: attrVals,
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
