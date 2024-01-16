package acre

import (
	"context"
	"errors"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/jackc/pgx/v5"
	acrev1 "github.com/opentdf/opentdf-v2-poc/gen/acre/v1"
	commonv1 "github.com/opentdf/opentdf-v2-poc/gen/common/v1"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/pkg/services"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

type ResourceEncoding struct {
	acrev1.UnimplementedResourcEncodingServiceServer
	dbClient *db.Client
}

func NewResourceEncoding(dbClient *db.Client, grpcServer *grpc.Server, mux *runtime.ServeMux) error {
	as := &ResourceEncoding{
		dbClient: dbClient,
	}
	acrev1.RegisterResourcEncodingServiceServer(grpcServer, as)
	err := acrev1.RegisterResourcEncodingServiceHandlerServer(context.Background(), mux, as)
	if err != nil {
		return errors.New("failed to register resource encoding service handler")
	}
	return nil
}

/*
	Resource Mappings
*/

func (s ResourceEncoding) CreateResourceMapping(ctx context.Context,
	req *acrev1.CreateResourceMappingRequest) (*acrev1.CreateResourceMappingResponse, error) {
	slog.Debug("creating resource mapping")

	// Set the version of the resource to 1 on create
	req.Mapping.Descriptor_.Version = 1

	resource, err := protojson.Marshal(req.Mapping)
	if err != nil {
		return &acrev1.CreateResourceMappingResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	err = s.dbClient.CreateResource(ctx, req.Mapping.Descriptor_, resource)
	if err != nil {
		slog.Error(services.ErrCreatingResource, slog.String("error", err.Error()))
		return &acrev1.CreateResourceMappingResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	return &acrev1.CreateResourceMappingResponse{}, nil
}

//nolint:dupl // there probably is duplication in these crud operations but its not worth refactoring yet.
func (s ResourceEncoding) ListResourceMappings(ctx context.Context,
	req *acrev1.ListResourceMappingsRequest) (*acrev1.ListResourceMappingsResponse, error) {
	mappings := &acrev1.ListResourceMappingsResponse{}

	rows, err := s.dbClient.ListResources(
		ctx,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
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
			mapping    = new(acrev1.ResourceMapping)
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

func (s ResourceEncoding) GetResourceMapping(ctx context.Context,
	req *acrev1.GetResourceMappingRequest) (*acrev1.GetResourceMappingResponse, error) {
	var (
		mapping = &acrev1.GetResourceMappingResponse{
			Mapping: new(acrev1.ResourceMapping),
		}
		id       int32
		bMapping []byte
	)

	row, err := s.dbClient.GetResource(
		ctx,
		req.Id,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
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

func (s ResourceEncoding) UpdateResourceMapping(ctx context.Context,
	req *acrev1.UpdateResourceMappingRequest) (*acrev1.UpdateResourceMappingResponse, error) {
	resource, err := protojson.Marshal(req.Mapping)
	if err != nil {
		return &acrev1.UpdateResourceMappingResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	err = s.dbClient.UpdateResource(
		ctx,
		req.Mapping.Descriptor_,
		resource,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
	)
	if err != nil {
		slog.Error(services.ErrUpdatingResource, slog.String("error", err.Error()))
		return &acrev1.UpdateResourceMappingResponse{},
			status.Error(codes.Internal, services.ErrUpdatingResource)
	}
	return &acrev1.UpdateResourceMappingResponse{}, nil
}

func (s ResourceEncoding) DeleteResourceMapping(ctx context.Context,
	req *acrev1.DeleteResourceMappingRequest) (*acrev1.DeleteResourceMappingResponse, error) {
	if err := s.dbClient.DeleteResource(
		ctx,
		req.Id,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
	); err != nil {
		slog.Error(services.ErrDeletingResource, slog.String("error", err.Error()))
		return &acrev1.DeleteResourceMappingResponse{},
			status.Error(codes.Internal, services.ErrDeletingResource)
	}
	return &acrev1.DeleteResourceMappingResponse{}, nil
}

/*
 Resource Groups
*/

func (s ResourceEncoding) CreateResourceGroup(ctx context.Context,
	req *acrev1.CreateResourceGroupRequest) (*acrev1.CreateResourceGroupResponse, error) {
	slog.Debug("creating resource group")

	// Set the version of the resource to 1 on create
	req.Group.Descriptor_.Version = 1

	resource, err := protojson.Marshal(req.Group)
	if err != nil {
		return &acrev1.CreateResourceGroupResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	err = s.dbClient.CreateResource(ctx, req.Group.Descriptor_, resource)
	if err != nil {
		slog.Error(services.ErrCreatingResource, slog.String("error", err.Error()))
		return &acrev1.CreateResourceGroupResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	return &acrev1.CreateResourceGroupResponse{}, nil
}

//nolint:dupl // there probably is duplication in these crud operations but its not worth refactoring yet.
func (s ResourceEncoding) ListResourceGroups(ctx context.Context,
	req *acrev1.ListResourceGroupsRequest) (*acrev1.ListResourceGroupsResponse, error) {
	groups := &acrev1.ListResourceGroupsResponse{}

	rows, err := s.dbClient.ListResources(
		ctx,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String(),
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
			group  = new(acrev1.ResourceGroup)
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

func (s ResourceEncoding) GetResourceGroup(ctx context.Context,
	req *acrev1.GetResourceGroupRequest) (*acrev1.GetResourceGroupResponse, error) {
	var (
		group = &acrev1.GetResourceGroupResponse{
			Group: new(acrev1.ResourceGroup),
		}
		id     int32
		bGroup []byte
	)

	row, err := s.dbClient.GetResource(
		ctx,
		req.Id, commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String(),
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

func (s ResourceEncoding) UpdateResourceGroup(ctx context.Context,
	req *acrev1.UpdateResourceGroupRequest) (*acrev1.UpdateResourceGroupResponse, error) {

	resource, err := protojson.Marshal(req.Group)
	if err != nil {
		return &acrev1.UpdateResourceGroupResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	err = s.dbClient.UpdateResource(
		ctx,
		req.Group.Descriptor_, resource,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String(),
	)
	if err != nil {
		slog.Error(services.ErrUpdatingResource, slog.String("error", err.Error()))
		return &acrev1.UpdateResourceGroupResponse{},
			status.Error(codes.Internal, services.ErrUpdatingResource)
	}
	return &acrev1.UpdateResourceGroupResponse{}, nil
}

func (s ResourceEncoding) DeleteResourceGroup(ctx context.Context,
	req *acrev1.DeleteResourceGroupRequest) (*acrev1.DeleteResourceGroupResponse, error) {
	if err := s.dbClient.DeleteResource(
		ctx,
		req.Id,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String(),
	); err != nil {
		slog.Error(services.ErrDeletingResource, slog.String("error", err.Error()))
		return &acrev1.DeleteResourceGroupResponse{},
			status.Error(codes.Internal, services.ErrDeletingResource)
	}
	return &acrev1.DeleteResourceGroupResponse{}, nil
}

/*
	Synonyms
*/

func (s ResourceEncoding) CreateResourceSynonym(ctx context.Context,
	req *acrev1.CreateResourceSynonymRequest) (*acrev1.CreateResourceSynonymResponse, error) {
	slog.Debug("creating resource synonym")

	// Set the version of the resource to 1 on create
	req.Synonym.Descriptor_.Version = 1

	resource, err := protojson.Marshal(req.Synonym)
	if err != nil {
		return &acrev1.CreateResourceSynonymResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	err = s.dbClient.CreateResource(ctx, req.Synonym.Descriptor_, resource)
	if err != nil {
		slog.Error(services.ErrCreatingResource, slog.String("error", err.Error()))
		return &acrev1.CreateResourceSynonymResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	return &acrev1.CreateResourceSynonymResponse{}, nil
}

//nolint:dupl // there probably is duplication in these crud operations but its not worth refactoring yet.
func (s ResourceEncoding) ListResourceSynonyms(ctx context.Context,
	req *acrev1.ListResourceSynonymsRequest) (*acrev1.ListResourceSynonymsResponse, error) {
	synonyms := &acrev1.ListResourceSynonymsResponse{}

	rows, err := s.dbClient.ListResources(
		ctx,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String(),
		req.Selector)
	if err != nil {
		slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
		return synonyms, status.Error(codes.Internal, services.ErrListingResource)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id       int32
			synonym  = new(acrev1.Synonyms)
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

func (s ResourceEncoding) GetResourceSynonym(ctx context.Context,
	req *acrev1.GetResourceSynonymRequest) (*acrev1.GetResourceSynonymResponse, error) {
	var (
		synonym = &acrev1.GetResourceSynonymResponse{
			Synonym: new(acrev1.Synonyms),
		}
		id       int32
		bSynonym []byte
	)

	row, err := s.dbClient.GetResource(
		ctx,
		req.Id,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String(),
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

func (s ResourceEncoding) UpdateResourceSynonym(ctx context.Context,
	req *acrev1.UpdateResourceSynonymRequest) (*acrev1.UpdateResourceSynonymResponse, error) {

	resource, err := protojson.Marshal(req.Synonym)
	if err != nil {
		return &acrev1.UpdateResourceSynonymResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	err = s.dbClient.UpdateResource(
		ctx,
		req.Synonym.Descriptor_,
		resource,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String(),
	)
	if err != nil {
		slog.Error(services.ErrUpdatingResource, slog.String("error", err.Error()))
		return &acrev1.UpdateResourceSynonymResponse{},
			status.Error(codes.Internal, services.ErrUpdatingResource)
	}
	return &acrev1.UpdateResourceSynonymResponse{}, nil
}

func (s ResourceEncoding) DeleteResourceSynonym(ctx context.Context,
	req *acrev1.DeleteResourceSynonymRequest) (*acrev1.DeleteResourceSynonymResponse, error) {
	if err := s.dbClient.DeleteResource(
		ctx,
		req.Id,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String(),
	); err != nil {
		slog.Error(services.ErrDeletingResource, slog.String("error", err.Error()))
		return &acrev1.DeleteResourceSynonymResponse{},
			status.Error(codes.Internal, services.ErrDeletingResource)
	}
	return &acrev1.DeleteResourceSynonymResponse{}, nil
}
