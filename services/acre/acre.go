package acre

import (
	"context"
	"errors"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/services"
	"github.com/opentdf/opentdf-v2-poc/services/common"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

type ResourceEncodingService struct {
	UnimplementedResourcEncodingServiceServer
	dbClient *db.Client
}

func NewResourceEncoding(dbClient *db.Client, grpcServer *grpc.Server, mux *runtime.ServeMux) error {
	as := &ResourceEncodingService{
		dbClient: dbClient,
	}
	RegisterResourcEncodingServiceServer(grpcServer, as)
	err := RegisterResourcEncodingServiceHandlerServer(context.Background(), mux, as)
	if err != nil {
		return errors.New("failed to register resource encoding service handler")
	}
	return nil
}

/*
	Resource Mappings
*/

func (s ResourceEncodingService) CreateResourceMapping(ctx context.Context,
	req *CreateResourceMappingRequest) (*CreateResourceMappingResponse, error) {
	slog.Debug("creating resource mapping")

	// Set the version of the resource to 1 on create
	req.Mapping.Descriptor_.Version = 1

	resource, err := protojson.Marshal(req.Mapping)
	if err != nil {
		return &CreateResourceMappingResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	err = s.dbClient.CreateResource(ctx, req.Mapping.Descriptor_, resource)
	if err != nil {
		slog.Error(services.ErrCreatingResource, slog.String("error", err.Error()))
		return &CreateResourceMappingResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	return &CreateResourceMappingResponse{}, nil
}

//nolint:dupl // there probably is duplication in these crud operations but its not worth refactoring yet.
func (s ResourceEncodingService) ListResourceMappings(ctx context.Context,
	req *ListResourceMappingsRequest) (*ListResourceMappingsResponse, error) {
	mappings := &ListResourceMappingsResponse{}

	rows, err := s.dbClient.ListResources(
		ctx,
		common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
		req.Selector,
	)
	if err != nil {
		slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
		return mappings, status.Error(codes.Internal, services.ErrListingResource)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id         int32
			mapping    = new(ResourceMapping)
			tmpMapping []byte
		)
		err = rows.Scan(&id, &tmpMapping)
		if err != nil {
			slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
			return mappings, status.Error(codes.Internal, services.ErrListingResource)
		}

		err = protojson.Unmarshal(tmpMapping, mapping)
		if err != nil {
			slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
			return mappings, status.Error(codes.Internal, services.ErrListingResource)
		}

		mapping.Descriptor_.Id = id
		mappings.Mappings = append(mappings.Mappings, mapping)
	}

	if err := rows.Err(); err != nil {
		slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
		return mappings, status.Error(codes.Internal, services.ErrListingResource)
	}

	return mappings, nil
}

func (s ResourceEncodingService) GetResourceMapping(ctx context.Context,
	req *GetResourceMappingRequest) (*GetResourceMappingResponse, error) {
	var (
		mapping = &GetResourceMappingResponse{
			Mapping: new(ResourceMapping),
		}
		id       int32
		bMapping []byte
	)

	row, err := s.dbClient.GetResource(
		ctx,
		req.Id,
		common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
	)
	if err != nil {
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return mapping, status.Error(codes.Internal, services.ErrGettingResource)
	}

	err = row.Scan(&id, &bMapping)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Error(services.ErrNotFound, slog.String("error", err.Error()))
			return mapping, status.Error(codes.NotFound, services.ErrNotFound)
		}
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return mapping, status.Error(codes.Internal, services.ErrGettingResource)
	}

	err = protojson.Unmarshal(bMapping, mapping.Mapping)
	if err != nil {
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return mapping, status.Error(codes.Internal, services.ErrGettingResource)
	}

	mapping.Mapping.Descriptor_.Id = id

	return mapping, nil
}

func (s ResourceEncodingService) UpdateResourceMapping(ctx context.Context,
	req *UpdateResourceMappingRequest) (*UpdateResourceMappingResponse, error) {
	resource, err := protojson.Marshal(req.Mapping)
	if err != nil {
		return &UpdateResourceMappingResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	err = s.dbClient.UpdateResource(
		ctx,
		req.Mapping.Descriptor_,
		resource,
		common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
	)
	if err != nil {
		slog.Error(services.ErrUpdatingResource, slog.String("error", err.Error()))
		return &UpdateResourceMappingResponse{},
			status.Error(codes.Internal, services.ErrUpdatingResource)
	}
	return &UpdateResourceMappingResponse{}, nil
}

func (s ResourceEncodingService) DeleteResourceMapping(ctx context.Context,
	req *DeleteResourceMappingRequest) (*DeleteResourceMappingResponse, error) {
	if err := s.dbClient.DeleteResource(
		ctx,
		req.Id,
		common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
	); err != nil {
		slog.Error(services.ErrDeletingResource, slog.String("error", err.Error()))
		return &DeleteResourceMappingResponse{},
			status.Error(codes.Internal, services.ErrDeletingResource)
	}
	return &DeleteResourceMappingResponse{}, nil
}

/*
 Resource Groups
*/

func (s ResourceEncodingService) CreateResourceGroup(ctx context.Context,
	req *CreateResourceGroupRequest) (*CreateResourceGroupResponse, error) {
	slog.Debug("creating resource group")

	// Set the version of the resource to 1 on create
	req.Group.Descriptor_.Version = 1

	resource, err := protojson.Marshal(req.Group)
	if err != nil {
		return &CreateResourceGroupResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	err = s.dbClient.CreateResource(ctx, req.Group.Descriptor_, resource)
	if err != nil {
		slog.Error(services.ErrCreatingResource, slog.String("error", err.Error()))
		return &CreateResourceGroupResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	return &CreateResourceGroupResponse{}, nil
}

//nolint:dupl // there probably is duplication in these crud operations but its not worth refactoring yet.
func (s ResourceEncodingService) ListResourceGroups(ctx context.Context,
	req *ListResourceGroupsRequest) (*ListResourceGroupsResponse, error) {
	groups := &ListResourceGroupsResponse{}

	rows, err := s.dbClient.ListResources(
		ctx,
		common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String(),
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
			group  = new(ResourceGroup)
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

func (s ResourceEncodingService) GetResourceGroup(ctx context.Context,
	req *GetResourceGroupRequest) (*GetResourceGroupResponse, error) {
	var (
		group = &GetResourceGroupResponse{
			Group: new(ResourceGroup),
		}
		id     int32
		bGroup []byte
	)

	row, err := s.dbClient.GetResource(
		ctx,
		req.Id, common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String(),
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

func (s ResourceEncodingService) UpdateResourceGroup(ctx context.Context,
	req *UpdateResourceGroupRequest) (*UpdateResourceGroupResponse, error) {

	resource, err := protojson.Marshal(req.Group)
	if err != nil {
		return &UpdateResourceGroupResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	err = s.dbClient.UpdateResource(
		ctx,
		req.Group.Descriptor_, resource,
		common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String(),
	)
	if err != nil {
		slog.Error(services.ErrUpdatingResource, slog.String("error", err.Error()))
		return &UpdateResourceGroupResponse{},
			status.Error(codes.Internal, services.ErrUpdatingResource)
	}
	return &UpdateResourceGroupResponse{}, nil
}

func (s ResourceEncodingService) DeleteResourceGroup(ctx context.Context,
	req *DeleteResourceGroupRequest) (*DeleteResourceGroupResponse, error) {
	if err := s.dbClient.DeleteResource(
		ctx,
		req.Id,
		common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String(),
	); err != nil {
		slog.Error(services.ErrDeletingResource, slog.String("error", err.Error()))
		return &DeleteResourceGroupResponse{},
			status.Error(codes.Internal, services.ErrDeletingResource)
	}
	return &DeleteResourceGroupResponse{}, nil
}

/*
	Synonyms
*/

func (s ResourceEncodingService) CreateResourceSynonym(ctx context.Context,
	req *CreateResourceSynonymRequest) (*CreateResourceSynonymResponse, error) {
	slog.Debug("creating resource synonym")

	// Set the version of the resource to 1 on create
	req.Synonym.Descriptor_.Version = 1

	resource, err := protojson.Marshal(req.Synonym)
	if err != nil {
		return &CreateResourceSynonymResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	err = s.dbClient.CreateResource(ctx, req.Synonym.Descriptor_, resource)
	if err != nil {
		slog.Error(services.ErrCreatingResource, slog.String("error", err.Error()))
		return &CreateResourceSynonymResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	return &CreateResourceSynonymResponse{}, nil
}

//nolint:dupl // there probably is duplication in these crud operations but its not worth refactoring yet.
func (s ResourceEncodingService) ListResourceSynonyms(ctx context.Context,
	req *ListResourceSynonymsRequest) (*ListResourceSynonymsResponse, error) {
	synonyms := &ListResourceSynonymsResponse{}

	rows, err := s.dbClient.ListResources(
		ctx,
		common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String(),
		req.Selector)
	if err != nil {
		slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
		return synonyms, status.Error(codes.Internal, services.ErrListingResource)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id       int32
			synonym  = new(Synonyms)
			bSynonym []byte
		)
		err = rows.Scan(&id, &bSynonym)
		if err != nil {
			slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
			return synonyms, status.Error(codes.Internal, services.ErrListingResource)
		}

		err = protojson.Unmarshal(bSynonym, synonym)
		if err != nil {
			slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
			return synonyms, status.Error(codes.Internal, services.ErrListingResource)
		}

		synonym.Descriptor_.Id = id
		synonyms.Synonyms = append(synonyms.Synonyms, synonym)
	}

	if err := rows.Err(); err != nil {
		slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
		return synonyms, status.Error(codes.Internal, services.ErrListingResource)
	}

	return synonyms, nil
}

func (s ResourceEncodingService) GetResourceSynonym(ctx context.Context,
	req *GetResourceSynonymRequest) (*GetResourceSynonymResponse, error) {
	var (
		synonym = &GetResourceSynonymResponse{
			Synonym: new(Synonyms),
		}
		id       int32
		bSynonym []byte
	)

	row, err := s.dbClient.GetResource(
		ctx,
		req.Id,
		common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String(),
	)
	if err != nil {
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return synonym, status.Error(codes.Internal, services.ErrGettingResource)
	}

	err = row.Scan(&id, &bSynonym)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Info(services.ErrNotFound, slog.Int("id", int(req.Id)))
			return synonym, status.Error(codes.NotFound, services.ErrNotFound)
		}
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return synonym, status.Error(codes.Internal, services.ErrGettingResource)
	}

	err = protojson.Unmarshal(bSynonym, synonym.Synonym)
	if err != nil {
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return synonym, status.Error(codes.Internal, services.ErrGettingResource)
	}

	synonym.Synonym.Descriptor_.Id = id

	return synonym, nil
}

func (s ResourceEncodingService) UpdateResourceSynonym(ctx context.Context,
	req *UpdateResourceSynonymRequest) (*UpdateResourceSynonymResponse, error) {

	resource, err := protojson.Marshal(req.Synonym)
	if err != nil {
		return &UpdateResourceSynonymResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	err = s.dbClient.UpdateResource(
		ctx,
		req.Synonym.Descriptor_,
		resource,
		common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String(),
	)
	if err != nil {
		slog.Error(services.ErrUpdatingResource, slog.String("error", err.Error()))
		return &UpdateResourceSynonymResponse{},
			status.Error(codes.Internal, services.ErrUpdatingResource)
	}
	return &UpdateResourceSynonymResponse{}, nil
}

func (s ResourceEncodingService) DeleteResourceSynonym(ctx context.Context,
	req *DeleteResourceSynonymRequest) (*DeleteResourceSynonymResponse, error) {
	if err := s.dbClient.DeleteResource(
		ctx,
		req.Id,
		common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String(),
	); err != nil {
		slog.Error(services.ErrDeletingResource, slog.String("error", err.Error()))
		return &DeleteResourceSynonymResponse{},
			status.Error(codes.Internal, services.ErrDeletingResource)
	}
	return &DeleteResourceSynonymResponse{}, nil
}
