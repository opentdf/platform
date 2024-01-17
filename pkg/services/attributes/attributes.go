package attributes

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/opentdf-v2-poc/gen/attributes"
	"github.com/opentdf/opentdf-v2-poc/gen/common"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/pkg/services"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

type Attributes struct {
	attributes.UnimplementedAttributesServiceServer
	dbClient *db.Client
}

func NewAttributesServer(dbClient *db.Client, g *grpc.Server, s *runtime.ServeMux) error {
	as := &Attributes{
		dbClient: dbClient,
	}
	attributes.RegisterAttributesServiceServer(g, as)
	err := attributes.RegisterAttributesServiceHandlerServer(context.Background(), s, as)
	if err != nil {
		return fmt.Errorf("failed to register attributes service handler: %w", err)
	}
	return nil
}

func (s Attributes) CreateAttribute(ctx context.Context,
	req *attributes.CreateAttributeRequest) (*attributes.CreateAttributeResponse, error) {
	slog.Debug("creating new attribute definition", slog.String("name", req.Definition.Name))

	// Set the version of the resource to 1 on create
	req.Definition.Descriptor_.Version = 1

	resource, err := protojson.Marshal(req.Definition)
	if err != nil {
		return &attributes.CreateAttributeResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	err = s.dbClient.CreateResource(ctx, req.Definition.Descriptor_, resource)
	if err != nil {
		slog.Error(services.ErrCreatingResource, slog.String("error", err.Error()))
		return &attributes.CreateAttributeResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}
	slog.Debug("created new attribute definition", slog.String("name", req.Definition.Name))

	return &attributes.CreateAttributeResponse{}, nil
}

func (s Attributes) CreateAttributeGroup(ctx context.Context,
	req *attributes.CreateAttributeGroupRequest) (*attributes.CreateAttributeGroupResponse, error) {
	slog.Debug("creating new attribute group definition")

	// Set the version of the resource to 1 on create
	req.Group.Descriptor_.Version = 1

	resource, err := protojson.Marshal(req.Group)
	if err != nil {
		return &attributes.CreateAttributeGroupResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	err = s.dbClient.CreateResource(ctx, req.Group.Descriptor_, resource)
	if err != nil {
		slog.Error(services.ErrCreatingResource, slog.String("error", err.Error()))
		return &attributes.CreateAttributeGroupResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}
	return &attributes.CreateAttributeGroupResponse{}, nil
}

func (s *Attributes) ListAttributes(ctx context.Context,
	req *attributes.ListAttributesRequest) (*attributes.ListAttributesResponse, error) {
	attributesList := &attributes.ListAttributesResponse{}

	rows, err := s.dbClient.ListResources(
		ctx,
		common.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION.String(),
		req.Selector,
	)

	if err != nil {
		slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
		return attributesList, status.Error(codes.Internal, services.ErrListingResource)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id          int32
			definition  = new(attributes.AttributeDefinition)
			bDefinition []byte
		)
		err = rows.Scan(&id, &bDefinition)
		if err != nil {
			slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
			return attributesList, status.Error(codes.Internal, services.ErrListingResource)
		}

		err = protojson.Unmarshal(bDefinition, definition)
		if err != nil {
			slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
			return attributesList, status.Error(codes.Internal, services.ErrListingResource)
		}

		definition.Descriptor_.Id = id
		attributesList.Definitions = append(attributesList.Definitions, definition)
	}

	if err := rows.Err(); err != nil {
		slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
		return attributesList, status.Error(codes.Internal, services.ErrListingResource)
	}

	return attributesList, nil
}

func (s *Attributes) ListAttributeGroups(ctx context.Context,
	req *attributes.ListAttributeGroupsRequest) (*attributes.ListAttributeGroupsResponse, error) {
	var (
		groups = new(attributes.ListAttributeGroupsResponse)
	)
	rows, err := s.dbClient.ListResources(
		ctx,
		common.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String(),
		req.Selector,
	)
	if err != nil {
		slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
		return groups, status.Error(codes.Internal, services.ErrListingResource)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id     int32
			group  = new(attributes.AttributeGroup)
			bGroup []byte
		)
		// var tmpDefinition []byte
		err = rows.Scan(&id, &bGroup)
		if err != nil {
			slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
			return groups, status.Error(codes.Internal, services.ErrListingResource)
		}

		err = protojson.Unmarshal(bGroup, group)
		if err != nil {
			slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
			return groups, status.Error(codes.Internal, services.ErrListingResource)
		}

		group.Descriptor_.Id = id
		groups.Groups = append(groups.Groups, group)
	}

	if err := rows.Err(); err != nil {
		slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
		return groups, status.Error(codes.Internal, services.ErrListingResource)
	}

	return groups, nil
}

//nolint:dupl // there probably is duplication in these crud operations but its not worth refactoring yet.
func (s *Attributes) GetAttribute(ctx context.Context,
	req *attributes.GetAttributeRequest) (*attributes.GetAttributeResponse, error) {
	var (
		definition = &attributes.GetAttributeResponse{
			Definition: new(attributes.AttributeDefinition),
		}
		id          int32
		bDefinition []byte
	)

	row, err := s.dbClient.GetResource(
		ctx,
		req.Id,
		common.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION.String(),
	)
	if err != nil {
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return definition, status.Error(codes.Internal, services.ErrGettingResource)
	}

	err = row.Scan(&id, &bDefinition)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Info(services.ErrNotFound, slog.Int("id", int(req.Id)))
			return definition, status.Error(codes.NotFound, services.ErrNotFound)
		}
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return definition, status.Error(codes.Internal, services.ErrGettingResource)
	}

	err = protojson.Unmarshal(bDefinition, definition.Definition)
	if err != nil {
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return definition, status.Error(codes.Internal, services.ErrGettingResource)
	}

	definition.Definition.Descriptor_.Id = id

	return definition, nil
}

//nolint:dupl // there probably is duplication in these crud operations but its not worth refactoring yet.
func (s *Attributes) GetAttributeGroup(ctx context.Context,
	req *attributes.GetAttributeGroupRequest) (*attributes.GetAttributeGroupResponse, error) {
	var (
		group = &attributes.GetAttributeGroupResponse{
			Group: new(attributes.AttributeGroup),
		}
		id     int32
		bGroup []byte
	)

	row, err := s.dbClient.GetResource(
		ctx,
		req.Id,
		common.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String(),
	)
	if err != nil {
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return group, status.Error(codes.Internal, services.ErrGettingResource)
	}

	err = row.Scan(&id, &bGroup)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Info(services.ErrNotFound, slog.Int("id", int(req.Id)))
			return group, status.Error(codes.NotFound, services.ErrNotFound)
		}
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return group, status.Error(codes.Internal, services.ErrGettingResource)
	}

	err = protojson.Unmarshal(bGroup, group.Group)
	if err != nil {
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return group, status.Error(codes.Internal, services.ErrGettingResource)
	}

	group.Group.Descriptor_.Id = id

	return group, nil
}

func (s *Attributes) UpdateAttribute(ctx context.Context,
	req *attributes.UpdateAttributeRequest) (*attributes.UpdateAttributeResponse, error) {
	resource, err := protojson.Marshal(req.Definition)
	if err != nil {
		return &attributes.UpdateAttributeResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	err = s.dbClient.UpdateResource(
		ctx,
		req.Definition.Descriptor_,
		resource,
		common.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION.String(),
	)
	if err != nil {
		slog.Error(services.ErrUpdatingResource, slog.String("error", err.Error()))
		return &attributes.UpdateAttributeResponse{},
			status.Error(codes.Internal, services.ErrUpdatingResource)
	}
	return &attributes.UpdateAttributeResponse{}, nil
}

func (s *Attributes) UpdateAttributeGroup(ctx context.Context,
	req *attributes.UpdateAttributeGroupRequest) (*attributes.UpdateAttributeGroupResponse, error) {
	resource, err := protojson.Marshal(req.Group)
	if err != nil {
		return &attributes.UpdateAttributeGroupResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	err = s.dbClient.UpdateResource(
		ctx,
		req.Group.Descriptor_, resource,
		common.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String(),
	)
	if err != nil {
		slog.Error(services.ErrUpdatingResource, slog.String("error", err.Error()))
		return &attributes.UpdateAttributeGroupResponse{},
			status.Error(codes.Internal, services.ErrUpdatingResource)
	}
	return &attributes.UpdateAttributeGroupResponse{}, nil
}

func (s *Attributes) DeleteAttribute(ctx context.Context,
	req *attributes.DeleteAttributeRequest) (*attributes.DeleteAttributeResponse, error) {
	if err := s.dbClient.DeleteResource(
		ctx,
		req.Id,
		common.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION.String(),
	); err != nil {
		slog.Error(services.ErrDeletingResource, slog.String("error", err.Error()))
		return &attributes.DeleteAttributeResponse{}, status.Error(codes.Internal,
			services.ErrDeletingResource)
	}
	return &attributes.DeleteAttributeResponse{}, nil
}

func (s *Attributes) DeleteAttributeGroup(ctx context.Context,
	req *attributes.DeleteAttributeGroupRequest) (*attributes.DeleteAttributeGroupResponse, error) {
	if err := s.dbClient.DeleteResource(
		ctx,
		req.Id,
		common.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String(),
	); err != nil {
		slog.Error(services.ErrDeletingResource, slog.String("error", err.Error()))
		return &attributes.DeleteAttributeGroupResponse{},
			status.Error(codes.Internal, services.ErrDeletingResource)
	}
	return &attributes.DeleteAttributeGroupResponse{}, nil
}
