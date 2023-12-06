package attributes

import (
	"context"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/jackc/pgx/v5"
	attributesv1 "github.com/opentdf/opentdf-v2-poc/gen/attributes/v1"
	commonv1 "github.com/opentdf/opentdf-v2-poc/gen/common/v1"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	attributePolicyType      = "attribute"
	attributeGroupPolicyType = "attribute_group"
)

type attributesServer struct {
	attributesv1.UnimplementedAttributesServiceServer
	dbClient *db.Client
}

func NewAttributesServer(dbClient *db.Client, g *grpc.Server, s *runtime.ServeMux) error {
	as := &attributesServer{
		dbClient: dbClient,
	}
	attributesv1.RegisterAttributesServiceServer(g, as)
	err := attributesv1.RegisterAttributesServiceHandlerServer(context.Background(), s, as)
	return err
}

func (s attributesServer) CreateAttribute(ctx context.Context, req *attributesv1.CreateAttributeRequest) (*attributesv1.CreateAttributeResponse, error) {
	slog.Debug("creating new attribute definition", slog.String("name", req.Definition.Name))
	var (
		err error
	)
	jsonResource, err := protojson.Marshal(req.Definition)
	if err != nil {
		slog.Error("error marshalling attribute", slog.String("error", err.Error()))
		return &attributesv1.CreateAttributeResponse{}, status.Error(codes.Internal, err.Error())
	}
	err = s.createResource(req.Definition.Descriptor_, jsonResource, attributePolicyType)
	if err != nil {
		slog.Error("error creating attribute", slog.String("error", err.Error()))
		return &attributesv1.CreateAttributeResponse{}, status.Error(codes.Internal, err.Error())
	}
	slog.Debug("created new attribute definition", slog.String("name", req.Definition.Name))

	return &attributesv1.CreateAttributeResponse{}, err
}

func (s attributesServer) CreateAttributeGroup(ctx context.Context, req *attributesv1.CreateAttributeGroupRequest) (*attributesv1.CreateAttributeGroupResponse, error) {
	slog.Debug("creating new attribute group definition")
	var err error

	jsonResource, err := protojson.Marshal(req.Group)
	if err != nil {
		slog.Info("error marshalling attribute group", slog.String("error", err.Error()))
		return &attributesv1.CreateAttributeGroupResponse{}, status.Error(codes.Internal, err.Error())
	}

	err = s.createResource(req.Group.Descriptor_, jsonResource, attributeGroupPolicyType)
	if err != nil {
		slog.Error("error creating attribute group", slog.String("error", err.Error()))
		return &attributesv1.CreateAttributeGroupResponse{}, status.Error(codes.Internal, err.Error())
	}
	return &attributesv1.CreateAttributeGroupResponse{}, nil
}

func (s attributesServer) createResource(descriptor *commonv1.ResourceDescriptor, resource []byte, policyType string) error {
	var err error

	args := pgx.NamedArgs{
		"namespace":   descriptor.Namespace,
		"version":     descriptor.Version,
		"fqn":         descriptor.Fqn,
		"label":       descriptor.Label,
		"description": descriptor.Description,
		"policytype":  policyType,
		"resource":    resource,
	}
	_, err = s.dbClient.Exec(context.TODO(), `
	INSERT INTO opentdf.resources (
		namespace,
		version,
		fqn,
		label,
		description,
		policytype,
		resource
	)
	VALUES (
		@namespace,
		@version,
		@fqn,
		@label,
		@description,
		@policytype,
		@resource
	)
	`, args)
	return err
}

func (s *attributesServer) ListAttributes(ctx context.Context, req *attributesv1.ListAttributesRequest) (*attributesv1.ListAttributesResponse, error) {
	attributes := &attributesv1.ListAttributesResponse{}
	args := pgx.NamedArgs{
		"policytype": attributePolicyType,
	}
	rows, err := s.dbClient.Query(context.TODO(), `
		SELECT
			id,
		  resource
		FROM opentdf.resources
		WHERE policytype = @policytype
	`, args)
	if err != nil {
		slog.Error("error listing attributes", slog.String("error", err.Error()))
		return attributes, status.Error(codes.Internal, err.Error())
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id          string
			definition  = new(attributesv1.AttributeDefinition)
			bDefinition []byte
		)
		// var tmpDefinition []byte
		err = rows.Scan(&id, &bDefinition)
		if err != nil {
			slog.Error("error listing attributes", slog.String("error", err.Error()))
			return attributes, status.Error(codes.Internal, err.Error())
		}
		err = protojson.Unmarshal(bDefinition, definition)
		if err != nil {
			slog.Error("error unmarshalling attribute", slog.String("error", err.Error()))
			return attributes, status.Error(codes.Internal, err.Error())
		}
		definition.Descriptor_.Id = id
		attributes.Definitions = append(attributes.Definitions, definition)
	}

	// We would need to keep column names in sync with the struct field names or retag the struct fields with protoc plugin
	// definitions, err := pgx.CollectRows(rows, pgx.RowToStructByName[attributesv1.AttributeDefinition])

	return attributes, nil
}

func (s *attributesServer) ListAttributeGroups(ctx context.Context, req *attributesv1.ListAttributeGroupsRequest) (*attributesv1.ListAttributeGroupsResponse, error) {
	var (
		attributeGroups = new(attributesv1.ListAttributeGroupsResponse)
		err             error
	)
	rows, err := s.listResources(attributeGroupPolicyType)
	if err != nil {
		slog.Error("error listing attribute groups", slog.String("error", err.Error()))
		return attributeGroups, status.Error(codes.Internal, err.Error())
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id     string
			group  = new(attributesv1.AttributeGroup)
			bGroup []byte
		)
		// var tmpDefinition []byte
		err = rows.Scan(&id, &bGroup)
		if err != nil {
			slog.Error("error listing attribute groups", slog.String("error", err.Error()))
			return attributeGroups, status.Error(codes.Internal, err.Error())
		}
		err = protojson.Unmarshal(bGroup, group)
		if err != nil {
			slog.Error("error unmarshalling attribute group", slog.String("error", err.Error()))
			return attributeGroups, status.Error(codes.Internal, err.Error())
		}
		group.Descriptor_.Id = id
		attributeGroups.Groups = append(attributeGroups.Groups, group)
	}
	return attributeGroups, nil
}

func (s *attributesServer) listResources(policyType string) (pgx.Rows, error) {
	args := pgx.NamedArgs{
		"policytype": policyType,
	}
	return s.dbClient.Query(context.TODO(), `
		SELECT
			id,
		  resource
		FROM opentdf.resources
		WHERE policytype = @policytype
	`, args)
}

func (s *attributesServer) GetAttribute(ctx context.Context, req *attributesv1.GetAttributeRequest) (*attributesv1.GetAttributeResponse, error) {
	var (
		definition = &attributesv1.GetAttributeResponse{
			Definition: new(attributesv1.AttributeDefinition),
		}
		bDefinition []byte
		err         error
		id          string
	)

	row := s.getResource(req.Id, attributePolicyType)
	if err != nil {
		slog.Error("error listing attributes", slog.String("error", err.Error()))
		return definition, status.Error(codes.Internal, err.Error())
	}

	err = row.Scan(&id, &bDefinition)
	if err != nil {
		if err == pgx.ErrNoRows {
			slog.Info("attribute not found", slog.String("id", req.Id))
			return definition, status.Error(codes.NotFound, "attribute not found")
		}
		slog.Error("error listing attributes", slog.String("error", err.Error()))
		return definition, status.Error(codes.Internal, err.Error())
	}
	err = protojson.Unmarshal(bDefinition, definition.Definition)
	if err != nil {
		slog.Error("error unmarshalling attribute", slog.String("error", err.Error()))
		return definition, status.Error(codes.Internal, err.Error())
	}
	definition.Definition.Descriptor_.Id = id

	if definition.Definition == nil {
		slog.Info("attribute not found", slog.String("id", req.Id))
		return definition, status.Error(codes.NotFound, "attribute not found")
	}

	return definition, nil
}

func (s *attributesServer) GetAttributeGroup(ctx context.Context, req *attributesv1.GetAttributeGroupRequest) (*attributesv1.GetAttributeGroupResponse, error) {
	var (
		group = &attributesv1.GetAttributeGroupResponse{
			Group: new(attributesv1.AttributeGroup),
		}
		bGroup []byte
		err    error
		id     string
	)

	row := s.getResource(req.Id, attributeGroupPolicyType)
	if err != nil {
		slog.Error("error listing attributes", slog.String("error", err.Error()))
		return group, err
	}

	err = row.Scan(&id, &bGroup)
	if err != nil {
		if err == pgx.ErrNoRows {
			slog.Info("attribute group not found", slog.String("id", req.Id))
			return group, status.Error(codes.NotFound, "attribute group not found")
		}
		slog.Error("error listing attributes", slog.String("error", err.Error()))
		return group, status.Error(codes.Internal, err.Error())
	}
	err = protojson.Unmarshal(bGroup, group.Group)
	if err != nil {
		slog.Error("error unmarshalling attribute group", slog.String("error", err.Error()))
		return group, status.Error(codes.Internal, err.Error())
	}
	group.Group.Descriptor_.Id = id

	return group, nil
}

func (s *attributesServer) getResource(id string, policyType string) pgx.Row {
	args := pgx.NamedArgs{
		"id":         id,
		"policytype": policyType,
	}
	return s.dbClient.QueryRow(context.TODO(), `
		SELECT
			id,
		  resource
		FROM opentdf.resources
		WHERE id = @id AND policytype = @policytype
	`, args)
}

func (s *attributesServer) UpdateAttribute(ctx context.Context, req *attributesv1.UpdateAttributeRequest) (*attributesv1.UpdateAttributeResponse, error) {
	jsonAttr, err := protojson.Marshal(req.Definition)
	if err != nil {
		slog.Error("error marshalling attribute", slog.String("error", err.Error()))
		return &attributesv1.UpdateAttributeResponse{}, status.Error(codes.Internal, err.Error())
	}
	err = s.updateResource(req.Definition.Descriptor_, jsonAttr, attributePolicyType)
	if err != nil {
		slog.Error("error updating attribute", slog.String("error", err.Error()))
		return &attributesv1.UpdateAttributeResponse{}, status.Error(codes.Internal, err.Error())
	}
	return &attributesv1.UpdateAttributeResponse{}, nil
}

func (s *attributesServer) UpdateAttributeGroup(ctx context.Context, req *attributesv1.UpdateAttributeGroupRequest) (*attributesv1.UpdateAttributeGroupResponse, error) {
	jsonAttrGroup, err := protojson.Marshal(req.Group)
	if err != nil {
		slog.Error("error marshalling attribute group", slog.String("error", err.Error()))
		return &attributesv1.UpdateAttributeGroupResponse{}, status.Error(codes.Internal, err.Error())
	}
	err = s.updateResource(req.Group.Descriptor_, jsonAttrGroup, attributeGroupPolicyType)
	if err != nil {
		slog.Error("error updating attribute group", slog.String("error", err.Error()))
		return &attributesv1.UpdateAttributeGroupResponse{}, status.Error(codes.Internal, err.Error())
	}
	return &attributesv1.UpdateAttributeGroupResponse{}, nil
}

func (s *attributesServer) updateResource(descriptor *commonv1.ResourceDescriptor, resource []byte, policyType string) error {
	var err error

	args := pgx.NamedArgs{
		"namespace":   descriptor.Namespace,
		"version":     descriptor.Version,
		"fqn":         descriptor.Fqn,
		"label":       descriptor.Label,
		"description": descriptor.Description,
		"policytype":  policyType,
		"resource":    resource,
		"id":          descriptor.Id,
	}
	_, err = s.dbClient.Exec(context.TODO(), `
	UPDATE opentdf.resources
	SET 
	namespace = @namespace,
	version = @version,
	description = @description,
	fqn = @fqn,
	label = @label,
	policyType = @policytype,
	resource = @resource
	WHERE id = @id
	`, args)
	return err
}

func (s *attributesServer) DeleteAttribute(ctx context.Context, req *attributesv1.DeleteAttributeRequest) (*attributesv1.DeleteAttributeResponse, error) {
	if err := s.deleteResource(req.Id, attributePolicyType); err != nil {
		slog.Error("error deleting attribute", slog.String("error", err.Error()))
		return &attributesv1.DeleteAttributeResponse{}, status.Error(codes.Internal, err.Error())
	}
	return &attributesv1.DeleteAttributeResponse{}, nil
}

func (s *attributesServer) DeleteAttributeGroup(ctx context.Context, req *attributesv1.DeleteAttributeGroupRequest) (*attributesv1.DeleteAttributeGroupResponse, error) {
	if err := s.deleteResource(req.Id, attributeGroupPolicyType); err != nil {
		slog.Error("error deleting attribute group", slog.String("error", err.Error()))
		return &attributesv1.DeleteAttributeGroupResponse{}, status.Error(codes.Internal, err.Error())
	}
	return &attributesv1.DeleteAttributeGroupResponse{}, nil
}

func (s *attributesServer) deleteResource(id string, policyType string) error {
	args := pgx.NamedArgs{
		"id":         id,
		"policytype": policyType,
	}
	_, err := s.dbClient.Query(context.TODO(), `
	DELETE FROM opentdf.resources
	WHERE id = @id AND policytype = @policytype
	`, args)
	return err
}
