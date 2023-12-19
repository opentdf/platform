package attributes

import (
	"context"
	"errors"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/jackc/pgx/v5"
	attributesv1 "github.com/opentdf/opentdf-v2-poc/gen/attributes/v1"
	commonv1 "github.com/opentdf/opentdf-v2-poc/gen/common/v1"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Attributes struct {
	attributesv1.UnimplementedAttributesServiceServer
	dbClient *db.Client
}

func NewAttributesServer(dbClient *db.Client, g *grpc.Server, s *runtime.ServeMux) error {
	as := &Attributes{
		dbClient: dbClient,
	}
	attributesv1.RegisterAttributesServiceServer(g, as)
	err := attributesv1.RegisterAttributesServiceHandlerServer(context.Background(), s, as)
	return err
}

func (s Attributes) CreateAttribute(ctx context.Context, req *attributesv1.CreateAttributeRequest) (*attributesv1.CreateAttributeResponse, error) {
	slog.Debug("creating new attribute definition", slog.String("name", req.Definition.Name))
	var (
		err error
	)

	// Set the version of the resource to 1 on create
	req.Definition.Descriptor_.Version = 1

	err = s.dbClient.CreateResource(req.Definition.Descriptor_, req.Definition)
	if err != nil {
		slog.Error("error creating attribute", slog.String("error", err.Error()))
		return &attributesv1.CreateAttributeResponse{}, status.Error(codes.Internal, err.Error())
	}
	slog.Debug("created new attribute definition", slog.String("name", req.Definition.Name))

	return &attributesv1.CreateAttributeResponse{}, nil
}

func (s Attributes) CreateAttributeGroup(ctx context.Context, req *attributesv1.CreateAttributeGroupRequest) (*attributesv1.CreateAttributeGroupResponse, error) {
	slog.Debug("creating new attribute group definition")

	err := s.dbClient.CreateResource(req.Group.Descriptor_, req.Group)
	if err != nil {
		slog.Error("error creating attribute group", slog.String("error", err.Error()))
		return &attributesv1.CreateAttributeGroupResponse{}, status.Error(codes.Internal, err.Error())
	}
	return &attributesv1.CreateAttributeGroupResponse{}, nil
}

func (s *Attributes) ListAttributes(ctx context.Context, req *attributesv1.ListAttributesRequest) (*attributesv1.ListAttributesResponse, error) {
	attributes := &attributesv1.ListAttributesResponse{}

	rows, err := s.dbClient.ListResources(
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION.String(),
		req.Selector,
	)

	if err != nil {
		slog.Error("error listing attribute definitions", slog.String("error", err.Error()))
		return attributes, status.Error(codes.Internal, err.Error())
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id         int32
			definition = new(attributesv1.AttributeDefinition)
		)
		err = rows.Scan(&id, &definition)
		if err != nil {
			slog.Error("error listing attributes", slog.String("error", err.Error()))
			return attributes, status.Error(codes.Internal, err.Error())
		}

		definition.Descriptor_.Id = id
		attributes.Definitions = append(attributes.Definitions, definition)
	}

	if err := rows.Err(); err != nil {
		slog.Error("error listing attributes", slog.String("error", err.Error()))
		return attributes, status.Error(codes.Internal, err.Error())
	}

	return attributes, nil
}

func (s *Attributes) ListAttributeGroups(ctx context.Context, req *attributesv1.ListAttributeGroupsRequest) (*attributesv1.ListAttributeGroupsResponse, error) {
	var (
		attributeGroups = new(attributesv1.ListAttributeGroupsResponse)
		err             error
	)
	rows, err := s.dbClient.ListResources(
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String(),
		req.Selector,
	)
	if err != nil {
		slog.Error("error listing attribute groups", slog.String("error", err.Error()))
		return attributeGroups, status.Error(codes.Internal, err.Error())
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id    int32
			group = new(attributesv1.AttributeGroup)
		)
		// var tmpDefinition []byte
		err = rows.Scan(&id, &group)
		if err != nil {
			slog.Error("error listing attribute groups", slog.String("error", err.Error()))
			return attributeGroups, status.Error(codes.Internal, err.Error())
		}

		group.Descriptor_.Id = id
		attributeGroups.Groups = append(attributeGroups.Groups, group)
	}

	if err := rows.Err(); err != nil {
		slog.Error("error listing attribute groups", slog.String("error", err.Error()))
		return attributeGroups, status.Error(codes.Internal, err.Error())
	}

	return attributeGroups, nil
}

func (s *Attributes) GetAttribute(ctx context.Context, req *attributesv1.GetAttributeRequest) (*attributesv1.GetAttributeResponse, error) {
	var (
		definition = &attributesv1.GetAttributeResponse{
			Definition: new(attributesv1.AttributeDefinition),
		}
		err error
		id  int32
	)

	row := s.dbClient.GetResource(
		req.Id,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION.String(),
	)

	err = row.Scan(&id, &definition.Definition)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Info("attribute not found", slog.Int("id", int(req.Id)))
			return definition, status.Error(codes.NotFound, "attribute not found")
		}
		slog.Error("error getting attribute", slog.String("error", err.Error()))
		return definition, status.Error(codes.Internal, err.Error())
	}

	definition.Definition.Descriptor_.Id = id

	return definition, nil
}

func (s *Attributes) GetAttributeGroup(ctx context.Context, req *attributesv1.GetAttributeGroupRequest) (*attributesv1.GetAttributeGroupResponse, error) {
	var (
		group = &attributesv1.GetAttributeGroupResponse{
			Group: new(attributesv1.AttributeGroup),
		}
		err error
		id  int32
	)

	row := s.dbClient.GetResource(
		req.Id,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String(),
	)

	err = row.Scan(&id, &group.Group)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Info("attribute group not found", slog.Int("id", int(req.Id)))
			return group, status.Error(codes.NotFound, "attribute group not found")
		}
		slog.Error("error getting attribute group", slog.String("error", err.Error()))
		return group, status.Error(codes.Internal, err.Error())
	}

	group.Group.Descriptor_.Id = id

	return group, nil
}

func (s *Attributes) UpdateAttribute(ctx context.Context, req *attributesv1.UpdateAttributeRequest) (*attributesv1.UpdateAttributeResponse, error) {
	err := s.dbClient.UpdateResource(
		req.Definition.Descriptor_,
		req.Definition,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION.String(),
	)
	if err != nil {
		slog.Error("issue updating attribute", slog.String("error", err.Error()))
		return &attributesv1.UpdateAttributeResponse{}, status.Error(codes.Internal, err.Error())
	}
	return &attributesv1.UpdateAttributeResponse{}, nil
}

func (s *Attributes) UpdateAttributeGroup(ctx context.Context, req *attributesv1.UpdateAttributeGroupRequest) (*attributesv1.UpdateAttributeGroupResponse, error) {
	err := s.dbClient.UpdateResource(
		req.Group.Descriptor_, req.Group,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String(),
	)
	if err != nil {
		slog.Error("issues updating attribute group", slog.String("error", err.Error()))
		return &attributesv1.UpdateAttributeGroupResponse{}, status.Error(codes.Internal, err.Error())
	}
	return &attributesv1.UpdateAttributeGroupResponse{}, nil
}

func (s *Attributes) DeleteAttribute(ctx context.Context, req *attributesv1.DeleteAttributeRequest) (*attributesv1.DeleteAttributeResponse, error) {
	if err := s.dbClient.DeleteResource(req.Id,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION.String(),
	); err != nil {
		slog.Error("issue deleting attribute", slog.String("error", err.Error()))
		return &attributesv1.DeleteAttributeResponse{}, status.Error(codes.Internal, err.Error())
	}
	return &attributesv1.DeleteAttributeResponse{}, nil
}

func (s *Attributes) DeleteAttributeGroup(ctx context.Context, req *attributesv1.DeleteAttributeGroupRequest) (*attributesv1.DeleteAttributeGroupResponse, error) {
	if err := s.dbClient.DeleteResource(
		req.Id,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String(),
	); err != nil {
		slog.Error("issue deleting attribute group", slog.String("error", err.Error()))
		return &attributesv1.DeleteAttributeGroupResponse{}, status.Error(codes.Internal, err.Error())
	}
	return &attributesv1.DeleteAttributeGroupResponse{}, nil
}
