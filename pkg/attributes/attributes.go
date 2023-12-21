package attributes

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/jackc/pgx/v5"
	attributesv1 "github.com/opentdf/opentdf-v2-poc/gen/attributes/v1"
	commonv1 "github.com/opentdf/opentdf-v2-poc/gen/common/v1"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	otdferrors "github.com/opentdf/opentdf-v2-poc/pkg/errors"
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

func (s Attributes) CreateAttribute(ctx context.Context,
	req *attributesv1.CreateAttributeRequest) (*attributesv1.CreateAttributeResponse, error) {
	slog.Debug("creating new attribute definition", slog.String("name", req.Definition.Name))

	// Set the version of the resource to 1 on create
	req.Definition.Descriptor_.Version = 1

	err := s.dbClient.CreateResource(ctx, req.Definition.Descriptor_, req.Definition)
	if err != nil {
		slog.Error(otdferrors.ErrCreatingResource.Error(), slog.String("error", err.Error()))
		return &attributesv1.CreateAttributeResponse{},
			status.Error(codes.Internal, fmt.Sprintf("%v: %v", otdferrors.ErrCreatingResource, err))
	}
	slog.Debug("created new attribute definition", slog.String("name", req.Definition.Name))

	return &attributesv1.CreateAttributeResponse{}, nil
}

func (s Attributes) CreateAttributeGroup(ctx context.Context,
	req *attributesv1.CreateAttributeGroupRequest) (*attributesv1.CreateAttributeGroupResponse, error) {
	slog.Debug("creating new attribute group definition")

	err := s.dbClient.CreateResource(ctx, req.Group.Descriptor_, req.Group)
	if err != nil {
		slog.Error(otdferrors.ErrCreatingResource.Error(), slog.String("error", err.Error()))
		return &attributesv1.CreateAttributeGroupResponse{},
			status.Error(codes.Internal, fmt.Sprintf("%v: %v", otdferrors.ErrCreatingResource, err))
	}
	return &attributesv1.CreateAttributeGroupResponse{}, nil
}

func (s *Attributes) ListAttributes(ctx context.Context,
	req *attributesv1.ListAttributesRequest) (*attributesv1.ListAttributesResponse, error) {
	attributes := &attributesv1.ListAttributesResponse{}

	rows, err := s.dbClient.ListResources(
		ctx,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION.String(),
		req.Selector,
	)

	if err != nil {
		slog.Error(otdferrors.ErrListingResource.Error(), slog.String("error", err.Error()))
		return attributes, status.Error(codes.Internal, fmt.Sprintf("%v: %v", otdferrors.ErrListingResource, err))
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id         int32
			definition = new(attributesv1.AttributeDefinition)
		)
		err = rows.Scan(&id, &definition)
		if err != nil {
			slog.Error(otdferrors.ErrListingResource.Error(), slog.String("error", err.Error()))
			return attributes, status.Error(codes.Internal, fmt.Sprintf("%v: %v", otdferrors.ErrListingResource, err))
		}

		definition.Descriptor_.Id = id
		attributes.Definitions = append(attributes.Definitions, definition)
	}

	if err := rows.Err(); err != nil {
		slog.Error(otdferrors.ErrListingResource.Error(), slog.String("error", err.Error()))
		return attributes, status.Error(codes.Internal, fmt.Sprintf("%v: %v", otdferrors.ErrListingResource, err))
	}

	return attributes, nil
}

func (s *Attributes) ListAttributeGroups(ctx context.Context,
	req *attributesv1.ListAttributeGroupsRequest) (*attributesv1.ListAttributeGroupsResponse, error) {
	var (
		groups = new(attributesv1.ListAttributeGroupsResponse)
	)
	rows, err := s.dbClient.ListResources(
		ctx,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String(),
		req.Selector,
	)
	if err != nil {
		slog.Error(otdferrors.ErrListingResource.Error(), slog.String("error", err.Error()))
		return groups, status.Error(codes.Internal, fmt.Sprintf("%v: %v", otdferrors.ErrListingResource, err))
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
			slog.Error(otdferrors.ErrListingResource.Error(), slog.String("error", err.Error()))
			return groups, status.Error(codes.Internal, fmt.Sprintf("%v: %v", otdferrors.ErrListingResource, err))
		}

		group.Descriptor_.Id = id
		groups.Groups = append(groups.Groups, group)
	}

	if err := rows.Err(); err != nil {
		slog.Error(otdferrors.ErrListingResource.Error(), slog.String("error", err.Error()))
		return groups, status.Error(codes.Internal, fmt.Sprintf("%v: %v", otdferrors.ErrListingResource, err))
	}

	return groups, nil
}

func (s *Attributes) GetAttribute(ctx context.Context,
	req *attributesv1.GetAttributeRequest) (*attributesv1.GetAttributeResponse, error) {
	var (
		definition = &attributesv1.GetAttributeResponse{
			Definition: new(attributesv1.AttributeDefinition),
		}
		id int32
	)

	row := s.dbClient.GetResource(
		ctx,
		req.Id,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION.String(),
	)

	err := row.Scan(&id, &definition.Definition)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Info(otdferrors.ErrNotFound.Error(), slog.Int("id", int(req.Id)))
			return definition, status.Error(codes.NotFound, otdferrors.ErrNotFound.Error())
		}
		slog.Error(otdferrors.ErrGettingResource.Error(), slog.String("error", err.Error()))
		return definition, status.Error(codes.Internal, fmt.Sprintf("%v: %v", otdferrors.ErrGettingResource, err))
	}

	definition.Definition.Descriptor_.Id = id

	return definition, nil
}

func (s *Attributes) GetAttributeGroup(ctx context.Context,
	req *attributesv1.GetAttributeGroupRequest) (*attributesv1.GetAttributeGroupResponse, error) {
	var (
		group = &attributesv1.GetAttributeGroupResponse{
			Group: new(attributesv1.AttributeGroup),
		}
		id int32
	)

	row := s.dbClient.GetResource(
		ctx,
		req.Id,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String(),
	)

	err := row.Scan(&id, &group.Group)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Info(otdferrors.ErrNotFound.Error(), slog.Int("id", int(req.Id)))
			return group, status.Error(codes.NotFound, otdferrors.ErrNotFound.Error())
		}
		slog.Error(otdferrors.ErrGettingResource.Error(), slog.String("error", err.Error()))
		return group, status.Error(codes.Internal, fmt.Sprintf("%v: %v", otdferrors.ErrGettingResource.Error(), err))
	}

	group.Group.Descriptor_.Id = id

	return group, nil
}

func (s *Attributes) UpdateAttribute(ctx context.Context,
	req *attributesv1.UpdateAttributeRequest) (*attributesv1.UpdateAttributeResponse, error) {
	err := s.dbClient.UpdateResource(
		ctx,
		req.Definition.Descriptor_,
		req.Definition,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION.String(),
	)
	if err != nil {
		slog.Error(otdferrors.ErrUpdatingResource.Error(), slog.String("error", err.Error()))
		return &attributesv1.UpdateAttributeResponse{},
			status.Error(codes.Internal, fmt.Sprintf("%v: %v", otdferrors.ErrUpdatingResource, err))
	}
	return &attributesv1.UpdateAttributeResponse{}, nil
}

func (s *Attributes) UpdateAttributeGroup(ctx context.Context,
	req *attributesv1.UpdateAttributeGroupRequest) (*attributesv1.UpdateAttributeGroupResponse, error) {
	err := s.dbClient.UpdateResource(
		ctx,
		req.Group.Descriptor_, req.Group,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String(),
	)
	if err != nil {
		slog.Error(otdferrors.ErrUpdatingResource.Error(), slog.String("error", err.Error()))
		return &attributesv1.UpdateAttributeGroupResponse{},
			status.Error(codes.Internal, fmt.Sprintf("%v: %v", otdferrors.ErrUpdatingResource, err))
	}
	return &attributesv1.UpdateAttributeGroupResponse{}, nil
}

func (s *Attributes) DeleteAttribute(ctx context.Context,
	req *attributesv1.DeleteAttributeRequest) (*attributesv1.DeleteAttributeResponse, error) {
	if err := s.dbClient.DeleteResource(
		ctx,
		req.Id,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION.String(),
	); err != nil {
		slog.Error(otdferrors.ErrDeletingResource.Error(), slog.String("error", err.Error()))
		return &attributesv1.DeleteAttributeResponse{}, status.Error(codes.Internal,
			fmt.Sprintf("%v: %v", otdferrors.ErrDeletingResource, err))
	}
	return &attributesv1.DeleteAttributeResponse{}, nil
}

func (s *Attributes) DeleteAttributeGroup(ctx context.Context,
	req *attributesv1.DeleteAttributeGroupRequest) (*attributesv1.DeleteAttributeGroupResponse, error) {
	if err := s.dbClient.DeleteResource(
		ctx,
		req.Id,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String(),
	); err != nil {
		slog.Error(otdferrors.ErrDeletingResource.Error(), slog.String("error", err.Error()))
		return &attributesv1.DeleteAttributeGroupResponse{},
			status.Error(codes.Internal, fmt.Sprintf("%v: %v", otdferrors.ErrDeletingResource, err))
	}
	return &attributesv1.DeleteAttributeGroupResponse{}, nil
}
